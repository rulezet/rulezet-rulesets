import "pe"
rule _Crinkler_V01V02__Rune_LHStubbe_and_Aske_Simon_Christensen_
{
	meta:
		description = "Crinkler V0.1-V0.2 -> Rune L.H.Stubbe and Aske Simon Christensen"
	strings:
		$0 = {B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9}
	condition:
		$0 at pe.entry_point
}