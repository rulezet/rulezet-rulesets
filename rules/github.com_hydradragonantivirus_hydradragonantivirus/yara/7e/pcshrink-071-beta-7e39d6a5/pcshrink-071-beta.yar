import "pe"
rule _PCShrink_071_beta_
{
	meta:
		description = "PCShrink 0.71 beta"
	strings:
		$0 = {01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00}
	condition:
		$0 at pe.entry_point
}