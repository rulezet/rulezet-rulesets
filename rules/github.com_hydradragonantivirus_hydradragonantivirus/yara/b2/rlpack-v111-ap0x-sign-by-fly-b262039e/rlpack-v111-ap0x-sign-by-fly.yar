import "pe"
rule _RLPack_V111__ap0x__Sign_by_fly_
{
	meta:
		description = "RLPack V1.11 -> ap0x ! Sign by fly"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB}
	condition:
		$0 at pe.entry_point
}