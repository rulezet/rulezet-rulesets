import "pe"
rule _ASProtect_v12x_New_Strain_
{
	meta:
		description = "ASProtect v1.2x (New Strain)"
	strings:
		$0 = {68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3}
	condition:
		$0 at pe.entry_point
}