import "pe"
rule _Upack_v02_Beta__Dwing_
{
	meta:
		description = "Upack v0.2 Beta -> Dwing"
	strings:
		$0 = {BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33}
	condition:
		$0 at pe.entry_point
}