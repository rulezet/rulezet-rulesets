import "pe"
rule _VITec_graphics_file_format_
{
	meta:
		description = "VITec graphics file format"
	strings:
		$0 = {00 5B 07 20 00 00 00 2C}
	condition:
		$0 at pe.entry_point
}