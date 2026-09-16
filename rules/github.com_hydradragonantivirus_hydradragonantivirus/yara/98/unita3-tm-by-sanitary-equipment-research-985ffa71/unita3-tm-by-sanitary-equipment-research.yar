import "pe"
rule _UNITA3_tm_by_Sanitary_Equipment_Research_
{
	meta:
		description = "UNITA3 (tm) by Sanitary Equipment Research"
	strings:
		$0 = {E8 ?? ?? 4D 5A 3E}
	condition:
		$0 at pe.entry_point
}