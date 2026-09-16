import "pe"
rule _UPX_v081__v084_Modified__Laszlo__Markus_
{
	meta:
		description = "UPX v0.81 - v0.84 Modified -> Laszlo & Markus"
	strings:
		$0 = {01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF}
	condition:
		$0 at pe.entry_point
}