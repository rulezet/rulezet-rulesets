import "pe"
rule _PolyCryptor_by_SMT_Version_v3v4_
{
	meta:
		description = "PolyCryptor by SMT Version %v3.%v4"
	strings:
		$0 = {EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29}
	condition:
		$0 at pe.entry_point
}