import "pe"
rule _PCPaintPictor_graphics_file_format_
{
	meta:
		description = "PCPaint/Pictor graphics file format"
	strings:
		$0 = {34 12 ?? ?? ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}