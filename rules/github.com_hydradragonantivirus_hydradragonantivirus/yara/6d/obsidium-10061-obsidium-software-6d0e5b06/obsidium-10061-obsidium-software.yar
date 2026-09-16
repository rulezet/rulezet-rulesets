import "pe"
rule _Obsidium_10061__Obsidium_Software_
{
	meta:
		description = "Obsidium 1.0.0.61 -> Obsidium Software"
	strings:
		$0 = {E8 AF 1C 00 00}
	condition:
		$0 at pe.entry_point
}