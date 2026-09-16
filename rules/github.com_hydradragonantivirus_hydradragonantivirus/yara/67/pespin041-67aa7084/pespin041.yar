rule pespin041
{
	meta:
		author = "PEiD"
		description = "PESpin 0.41 -> cyberbob"
		group = "158"
		function = "0"
	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 02 D2 46 }
	condition:
		$a0
}