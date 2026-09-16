rule drweb
{
	meta:
		author = "PEiD"
		description = "Dr.Web Virus-Finding Engine -> InSoft EDV-Systeme"
		group = "444"
		function = "0"
	strings:
		$a0 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }
	condition:
		$a0
}