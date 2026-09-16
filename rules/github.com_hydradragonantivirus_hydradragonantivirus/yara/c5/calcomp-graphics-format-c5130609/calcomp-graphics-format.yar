import "pe"
rule _CalComp_Graphics_format_
{
	meta:
		description = "CalComp Graphics format"
	strings:
		$0 = {02 50 0A}
	condition:
		$0 at pe.entry_point
}