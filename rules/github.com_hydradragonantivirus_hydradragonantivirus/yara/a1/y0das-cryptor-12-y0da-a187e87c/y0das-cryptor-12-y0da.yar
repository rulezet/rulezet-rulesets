import "pe"
rule _y0das_Cryptor_12__y0da_
{
	meta:
		description = "y0da's Cryptor 1.2 -> y0da"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC}
	condition:
		$0 at pe.entry_point
}