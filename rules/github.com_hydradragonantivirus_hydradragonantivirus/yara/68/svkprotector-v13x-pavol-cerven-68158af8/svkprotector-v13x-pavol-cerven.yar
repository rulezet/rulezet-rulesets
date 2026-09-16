import "pe"
rule _SVKProtector_v13x__Pavol_Cerven_
{
	meta:
		description = "SVK-Protector v1.3x -> Pavol Cerven"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? ?? 00 64 A0 23}
	condition:
		$0 at pe.entry_point
}