import "pe"
rule _Banners_banner_file_
{
	meta:
		description = "Banner's banner file"
	strings:
		$0 = {D1 BA 01 00}
	condition:
		$0 at pe.entry_point
}