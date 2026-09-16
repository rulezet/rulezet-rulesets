import "pe"
rule _PseudoSigner_02_FSG_10_
{
	meta:
		description = "PseudoSigner 0.2 [FSG 1.0"
	strings:
		$0 = {90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B}
	condition:
		$0 at pe.entry_point
}