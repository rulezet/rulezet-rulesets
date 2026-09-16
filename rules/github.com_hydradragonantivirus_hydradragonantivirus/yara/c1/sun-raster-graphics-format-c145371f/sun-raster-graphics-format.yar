import "pe"
rule _Sun_Raster_Graphics_format_
{
	meta:
		description = "Sun Raster Graphics format"
	strings:
		$0 = {59 A6 6A 95}
	condition:
		$0 at pe.entry_point
}