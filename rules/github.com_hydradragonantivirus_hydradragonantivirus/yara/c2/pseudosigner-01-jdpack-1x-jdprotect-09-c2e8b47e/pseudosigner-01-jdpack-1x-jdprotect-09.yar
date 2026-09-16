import "pe"
rule _PseudoSigner_01_JDPack_1x__JDProtect_09_
{
	meta:
		description = "PseudoSigner 0.1 [JDPack 1.x / JDProtect 0.9"
	strings:
		$0 = {60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9}
		$1 = {60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}