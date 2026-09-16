rule _Upack_v032_Beta_Patch__Dwing_
{
	meta:
		description = "Upack v0.32 Beta (Patch) -> Dwing"
	strings:
		$0 = {BE 88 01 ?? ?? AD 50 ?? AD 91 F3 A5}
	condition:
		$0
}