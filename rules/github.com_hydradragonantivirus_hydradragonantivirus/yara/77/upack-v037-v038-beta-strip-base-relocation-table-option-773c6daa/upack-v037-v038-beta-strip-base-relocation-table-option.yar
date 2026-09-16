import "pe"
rule _Upack_v037__v038_Beta_Strip_base_relocation_table_Option_
{
	meta:
		description = "Upack v0.37 ~ v0.38 Beta (Strip base relocation table Option)"
	strings:
		$0 = {53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33}
		$1 = {52 CC 00 00 00 00 ?? ?? ?? ?? 09 ?? 08 ?? 08}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}