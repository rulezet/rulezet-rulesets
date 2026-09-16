rule realbasicplug
{
	meta:
		author = "PEiD"
		description = "REALBasic internal plugin"
		group = "555"
		function = "0"
	strings:
		$a0 = { 55 89 E5 53 56 8B 75 0C 85 F6 57 8B 5D 10 B8 01 00 00 00 75 1B 83 3D 28 C2 00 10 00 75 12 8D 65 }
	condition:
		$a0
}