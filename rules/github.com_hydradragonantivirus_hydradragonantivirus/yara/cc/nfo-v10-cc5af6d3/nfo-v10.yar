import "pe"
rule _NFO_v10_
{
	meta:
		description = "NFO v1.0"
	strings:
		$0 = {60 9C 8D}
	condition:
		$0 at pe.entry_point
}