import "pe"
rule upx81_84_h
{
	meta:
		author = "PEiD"
		description = "UPX 0.81 - 0.84 modified -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 ?? ?? ?? 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }
	condition:
		$a0 at pe.entry_point
}