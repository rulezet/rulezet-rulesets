import "pe"
rule _ACProtect_V13X__risco_
{
	meta:
		description = "ACProtect V1.3X -> risco"
	strings:
		$0 = {60 50 E8 01 00 00 00 75 83}
	condition:
		$0 at pe.entry_point
}