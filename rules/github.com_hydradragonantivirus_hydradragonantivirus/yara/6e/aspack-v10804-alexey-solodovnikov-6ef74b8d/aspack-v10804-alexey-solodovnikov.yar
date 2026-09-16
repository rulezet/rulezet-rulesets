import "pe"
rule _ASPack_v10804__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.08.04 -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 41 06 00 00 EB 41}
	condition:
		$0 at pe.entry_point
}