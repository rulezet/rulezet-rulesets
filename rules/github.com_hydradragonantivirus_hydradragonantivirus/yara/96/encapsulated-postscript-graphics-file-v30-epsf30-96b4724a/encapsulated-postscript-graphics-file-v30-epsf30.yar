import "pe"
rule _Encapsulated_Postscript_graphics_file_v30_EPSF30_
{
	meta:
		description = "Encapsulated Postscript graphics file v3.0 EPSF-3.0"
	strings:
		$0 = {25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 2E 30}
	condition:
		$0 at pe.entry_point
}