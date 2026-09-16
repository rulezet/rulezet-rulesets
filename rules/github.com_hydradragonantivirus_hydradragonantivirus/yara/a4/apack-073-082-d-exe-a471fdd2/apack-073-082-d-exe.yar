import "pe"
rule _aPack_073__082_d_EXE_
{
	meta:
		description = "aPack 0.73 - 0.82 -d [EXE]"
	strings:
		$0 = {8C C8 8E D8 05 00 00 8E C0 50 BE 00 00 33 FF FC B6 01 BD 00 00}
	condition:
		$0 at pe.entry_point
}