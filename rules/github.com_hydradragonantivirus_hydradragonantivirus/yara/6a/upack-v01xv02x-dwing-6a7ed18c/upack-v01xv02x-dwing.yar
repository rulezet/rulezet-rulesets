import "pe"
rule _Upack_V01XV02X__Dwing_
{
	meta:
		description = "Upack V0.1X-V0.2X -> Dwing"
	strings:
		$0 = {1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C}
	condition:
		$0 at pe.entry_point
}