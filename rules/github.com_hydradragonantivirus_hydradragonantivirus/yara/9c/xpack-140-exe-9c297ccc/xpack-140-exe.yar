import "pe"
rule _XPack_140_EXE_
{
	meta:
		description = "XPack 1.40 [EXE]"
	strings:
		$0 = {2E 83 26 01 01 00 8B EC EB 01 E8 FA B8 C9 03 EB 01 9A FF E0 F3 03 FD 03 5E 04 86 04 E2 00 98 04 CF 00 82 04 AC 00 85 04 AA 00 7A 04 FC 00 33 C0 8E D0 BC 10 00 2E 8F 06 0A 04 2E 8F 06 0F 04 EB 01 9A 0E 2E FF 36 B1 03 5F EB 01 9A 17 8B E5 FB}
	condition:
		$0 at pe.entry_point
}