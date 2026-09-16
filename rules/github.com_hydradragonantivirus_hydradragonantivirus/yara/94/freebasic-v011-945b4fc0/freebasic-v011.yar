import "pe"
rule _FreeBASIC_v011_
{
	meta:
		description = "FreeBASIC v0.11"
	strings:
		$0 = {E8 ?? ?? 00 00 E8 01 00 00 00 C3 55 89 E5}
	condition:
		$0 at pe.entry_point
}