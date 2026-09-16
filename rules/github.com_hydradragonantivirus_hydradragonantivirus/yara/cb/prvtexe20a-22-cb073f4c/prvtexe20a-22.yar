rule prvtexe20a_22
{
	meta:
		author = "PEiD"
		description = "Private Exe 2.0a"
		group = "164"
		function = "0"
	strings:
		$a0 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }
	condition:
		$a0
}