import "pe"
rule _PseudoSigner_02_Lockless_Intro_Pack__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Lockless Intro Pack] --> Anorganix"
	strings:
		$0 = {2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD}
	condition:
		$0 at pe.entry_point
}