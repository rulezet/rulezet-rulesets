import "pe"
rule _Trap_120_EXE_
{
	meta:
		description = "Trap 1.20 [EXE]"
	strings:
		$0 = {E8 00 00 5B 83 C3 28 90 8B D3 E8 01 00 01 5B 2E 80 3F 00 74 16 90 90 8B DA B9 A2 03 2E C0 07 39 2E 80 37 00 2E 80 2F 00 43 E2 F1}
	condition:
		$0 at pe.entry_point
}