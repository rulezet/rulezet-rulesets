import "pe"
rule _Freshbind_v20__gFresh_
{
	meta:
		description = "Freshbind v2.0 -> gFresh"
	strings:
		$0 = {64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00}
	condition:
		$0 at pe.entry_point
}