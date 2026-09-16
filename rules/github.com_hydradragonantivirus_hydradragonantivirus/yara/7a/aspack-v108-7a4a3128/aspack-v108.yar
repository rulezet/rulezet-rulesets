import "pe"
rule _ASPack_v108_
{
	meta:
		description = "ASPack v1.08"
	strings:
		$0 = {90 90 75 01 FF}
		$1 = {90 90 90 75 01 FF}
		$2 = {90 90 90 75 90}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}