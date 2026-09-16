import "pe"
rule _xPEP_03x__xIkUg_
{
	meta:
		description = "xPEP 0.3x -> xIkUg"
	strings:
		$0 = {55 53 56 51 52 57 E8 16 00 00 00}
	condition:
		$0 at pe.entry_point
}