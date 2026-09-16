import "pe"
rule _Vx_SK_
{
	meta:
		description = "Vx: SK"
	strings:
		$0 = {CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09}
	condition:
		$0 at pe.entry_point
}