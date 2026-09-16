import "pe"
rule _N0Ps_Shit_Protector_0002b_
{
	meta:
		description = "N0Ps Shit Protector 0.002b"
	strings:
		$0 = {9C 58 25 FF FE 50 9D 8B D4 8C D3 8E D3 BC 03 00 8B E2 8E D3 9C 58 A9 00 01 75 01 2E E8 00 00 5D 81 ED B2 07 B8 A8 07 03 C5 2E 81 B6 B8 07 FF FE 50 58 8B F4 2E 8B BE C3 07 81 EF 4E 58 2B F7 8B 1C 83 C3 32 FF E3 2E 33 FF 8E DF 8E C7 8B F7 FA}
	condition:
		$0 at pe.entry_point
}