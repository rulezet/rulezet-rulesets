import "pe"
rule _XPack_139_EXE_
{
	meta:
		description = "XPack 1.39 [EXE]"
	strings:
		$0 = {2E C7 06 01 01 00 00 8B EC EB 01 E8 2E C6 06 0E 05 FA EB 00 9A BC 1C 05 2E C6 06 1A 05 C3 EB 00 9A 90 42 05 06 09 95 19 99 26 03 62 F7 03 74 05 8F 05 1A 06 50 06 E2 00 64 06 CF 00 4C 06 AC 00 4F 06 AA 00 43 06 FC 00 33 E4 8E D4 83 C4 10 2E}
	condition:
		$0 at pe.entry_point
}