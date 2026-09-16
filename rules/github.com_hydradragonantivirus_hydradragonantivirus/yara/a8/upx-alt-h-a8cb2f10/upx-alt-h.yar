import "pe"
rule upx_alt_h
{
	meta:
		author = "PEiD"
		description = "UPX alternative stub -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 ?? ?? ?? 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }
	condition:
		$a0 at pe.entry_point
}