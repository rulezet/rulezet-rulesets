import "pe"
rule _EXE_Shield_v29__Exeshield_Corp_
{
	meta:
		description = "EXE Shield v2.9 -> Exeshield Corp."
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC}
	condition:
		$0 at pe.entry_point
}