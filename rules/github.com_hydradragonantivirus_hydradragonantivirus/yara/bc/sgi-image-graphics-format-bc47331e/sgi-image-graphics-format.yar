import "pe"
rule _SGI_Image_Graphics_format_
{
	meta:
		description = "SGI Image Graphics format"
	strings:
		$0 = {01 DA 00 01 00 03}
	condition:
		$0 at pe.entry_point
}