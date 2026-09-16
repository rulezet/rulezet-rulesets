import "pe"
rule msvcspx1
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 6.0 SPx Method 1"
		group = "15"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22 }
	condition:
		$a0 at pe.entry_point
}