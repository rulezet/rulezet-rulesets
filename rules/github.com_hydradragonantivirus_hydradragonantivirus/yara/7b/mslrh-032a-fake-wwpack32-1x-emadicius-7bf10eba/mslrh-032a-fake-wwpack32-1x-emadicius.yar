import "pe"
rule _MSLRH_032a_fake_WWPack32_1x__emadicius_
{
	meta:
		description = "MSLRH 0.32a (fake WWPack32 1.x) -> emadicius"
	strings:
		$0 = {53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 20 64 65 63 6F 6D 70 72 65 73 73 69 6F 6E 20 72 6F 75 74 69 6E 65 20 76 65 72 73 69 6F 6E 20 31 2E 31 32 0D 0A 28 63 29 20 31 39 39 38 20 50 69 6F 74 72 20 57 61 72 65 7A 61 6B 20 61 6E 64 20 52}
	condition:
		$0 at pe.entry_point
}