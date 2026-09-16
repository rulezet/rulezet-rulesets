import "pe"
rule _UPX_072_
{
	meta:
		description = "UPX 0.72"
	strings:
		$0 = {60 E8 00 00 00 00 83 CD FF 31 DB 5E}
	condition:
		$0 at pe.entry_point
}