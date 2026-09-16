rule cdcops
{
	meta:
		author = "PEiD"
		description = "CD-Cops II -> Link Data Security"
		group = "108"
		function = "0"
	strings:
		$a0 = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D }
	condition:
		$a0
}