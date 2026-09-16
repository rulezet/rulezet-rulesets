import "pe"
rule _aPack_058__082_1_EXE_
{
	meta:
		description = "aPack 0.58 - 0.82 (1) [EXE]"
	strings:
		$0 = {1E 06 8C C8 8E D8 05 00 00 8E C0 50 BE 00 00 33 FF FC B6 01 BD}
	condition:
		$0 at pe.entry_point
}