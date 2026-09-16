import "pe"
rule _Windows_Icon_Graphics_format_
{
	meta:
		description = "Windows Icon Graphics format"
	strings:
		$0 = {00 00 01 00}
	condition:
		$0 at pe.entry_point
}