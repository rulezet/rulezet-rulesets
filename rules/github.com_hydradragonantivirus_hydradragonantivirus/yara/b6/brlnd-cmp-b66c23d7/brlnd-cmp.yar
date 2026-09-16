rule brlnd_cmp
{
	meta:
		author = "PEiD"
		description = "Borland Component"
		group = "31"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? FF 8D 40 }
	condition:
		$a0
}