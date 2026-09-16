import "pe"
rule _EP_v02__CoDe_Inside_
{
	meta:
		description = "EP v0.2 -> CoDe_Inside"
	strings:
		$0 = {6A 00 60 E9 01 01 00 00}
	condition:
		$0 at pe.entry_point
}