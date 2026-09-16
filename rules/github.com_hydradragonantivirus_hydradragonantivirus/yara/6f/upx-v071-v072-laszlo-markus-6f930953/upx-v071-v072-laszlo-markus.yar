import "pe"
rule _UPX_v071__v072__Laszlo__Markus_
{
	meta:
		description = "UPX v0.71 - v0.72 -> Laszlo & Markus"
	strings:
		$0 = {60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07}
	condition:
		$0 at pe.entry_point
}