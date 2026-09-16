rule nfo1
{
	meta:
		author = "PEiD"
		description = "NFO 1.0 -> bart/CrackPL"
		group = "131"
		function = "0"
	strings:
		$a0 = { 60 9C 8D 50 12 2B C9 B1 1E 8A 02 34 ?? 88 02 42 E2 F7 }
	condition:
		$a0
}