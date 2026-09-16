import "pe"
rule _PseudoSigner_02_Borland_Cue_1999_
{
	meta:
		description = "PseudoSigner 0.2 [Borland Cue 1999"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 ?? ?? ?? ?? A3}
	condition:
		$0 at pe.entry_point
}