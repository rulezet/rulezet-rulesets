import "pe"
rule iworm
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> I-Worm HYBRIS"
		group = "800"
		function = "0"
	strings:
		$a0 = { EB 16 A8 54 ?? ?? 47 41 42 4C 4B 43 47 43 ?? ?? ?? ?? ?? ?? 52 49 53 ?? FC 68 4C 70 40 ?? FF 15 }
	condition:
		$a0 at pe.entry_point
}