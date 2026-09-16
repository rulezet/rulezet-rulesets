import "pe"
rule _PseudoSigner_02_NorthStar_PE_Shrinker_13_
{
	meta:
		description = "PseudoSigner 0.2 [NorthStar PE Shrinker 1.3"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00}
	condition:
		$0 at pe.entry_point
}