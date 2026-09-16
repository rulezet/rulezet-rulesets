import "pe"
rule _Lotus_Graphics_format_
{
	meta:
		description = "Lotus Graphics format"
	strings:
		$0 = {01 00 00 00 01 00 08 00}
	condition:
		$0 at pe.entry_point
}