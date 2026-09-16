rule stealthpe21
{
	meta:
		author = "PEiD"
		description = "Ste@lth PE 2.10 -> BGCorp"
		group = "176"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? BA ?? ?? ?? ?? B9 00 10 40 00 31 01 83 C1 04 4A 75 F8 EB C0 }
	condition:
		$a0
}