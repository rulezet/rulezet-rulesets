import "pe"
rule _Borland_C__Borland_Builder_
{
	meta:
		description = "Borland C / Borland Builder"
	strings:
		$0 = {3B CF 76 05 2B CF FC F3 AA 59}
	condition:
		$0 at pe.entry_point
}