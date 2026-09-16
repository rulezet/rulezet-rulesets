import "pe"
rule _DrWeb_v400p_Virus_DataBase_
{
	meta:
		description = "DrWeb v4.00+ Virus DataBase"
	strings:
		$0 = {49 44 52 57}
	condition:
		$0 at pe.entry_point
}