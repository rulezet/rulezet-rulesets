rule TEST_false_positive_plain_fnv1a_in_x64
{
    meta:
        description = "This rule detects x64 implementations of standard fnv1a just by looking for the standard fnv64a_offset and fnv64a_prime (unless bitshifting is used instead of multiplication). This rule would have found the SUNBURST backdoor at Solarwinds but will also find any other programm which implements fnv1a. Just useful for developers, pls check if that fnv1a was put there by you ;)"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
        author = "Arnim Rupp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		date = "2020-12-22"
		score = 10
    strings:
		$fnv64a_offset = { 25 23 22 84 e4 9c f2 cb }
		$fnv64a_prime = { B3 01 00 00 00 01 }
    condition:
				( uint16(0) == 0x5a4d or uint32be(0) == 0x7f454c46 ) and all of them
}