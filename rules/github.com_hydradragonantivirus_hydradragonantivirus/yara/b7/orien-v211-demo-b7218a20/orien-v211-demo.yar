import "pe"
rule _ORiEN_v211_DEMO_
{
	meta:
		description = "ORiEN v2.11 (DEMO)"
	strings:
		$0 = {60 E8 01 E8 83 C4 04 E8 01 E9 5D 81 ED D3 22 40 E8 04 02 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47}
	condition:
		$0 at pe.entry_point
}