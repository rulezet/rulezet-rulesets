import "pe"
rule _Image_Systems_Technology_Graphics_format_
{
	meta:
		description = "Image Systems Technology Graphics format"
	strings:
		$0 = {03 3A ?? ?? 00 ?? 00 00}
	condition:
		$0 at pe.entry_point
}