import "pe"
rule _Vx_Einstein_
{
	meta:
		description = "Vx: Einstein"
	strings:
		$0 = {00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42}
	condition:
		$0 at pe.entry_point
}