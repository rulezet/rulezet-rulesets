import "pe"
rule _Thoreador_12__Sergi_
{
	meta:
		description = "Thoreador 1.2 -> Sergi"
	strings:
		$0 = {55 E8 00 00 00 00 5D 83 ED 06 81 ED E2 00 00 00 60 EB 6F 90 90 90}
	condition:
		$0 at pe.entry_point
}