import "pe"
rule _SimbiOZ_13__Extranger_
{
	meta:
		description = "SimbiOZ 1.3 -> Extranger"
	strings:
		$0 = {57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3}
	condition:
		$0 at pe.entry_point
}