import "pe"
rule yc11
{
	meta:
		author = "PEiD"
		description = "yoda's cryptor 1.1"
		group = "195"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 8A 1C 40 ?? B9 9E ?? ?? ?? 8D BD 4C 23 40 ?? 8B F7 33 }
	condition:
		$a0 at pe.entry_point
}