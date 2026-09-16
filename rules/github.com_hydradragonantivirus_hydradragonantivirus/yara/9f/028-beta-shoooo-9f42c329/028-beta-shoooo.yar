import "pe"
rule __028_beta__shoooo_
{
	meta:
		description = "0.28 beta -> shoooo"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B}
	condition:
		$0 at pe.entry_point
}