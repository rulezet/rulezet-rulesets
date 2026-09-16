import "pe"
rule _PseudoSigner_02_BJFNT_11b__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [.BJFNT 1.1b] --> Anorganix"
	strings:
		$0 = {EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90}
	condition:
		$0 at pe.entry_point
}