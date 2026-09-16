import "pe"
rule _Obsidium_1200__Obsidium_Software_
{
	meta:
		description = "Obsidium 1.2.0.0 -> Obsidium Software"
	strings:
		$0 = {EB 02 ?? ?? E8 3F 1E 00 00}
	condition:
		$0 at pe.entry_point
}