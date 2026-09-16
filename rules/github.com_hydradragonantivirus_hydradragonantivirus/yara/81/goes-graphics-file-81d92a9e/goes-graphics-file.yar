import "pe"
rule _GOES_graphics_file_
{
	meta:
		description = "GOES graphics file"
	strings:
		$0 = {C8 C4 D9 40 C1 D9 C5 C1}
	condition:
		$0 at pe.entry_point
}