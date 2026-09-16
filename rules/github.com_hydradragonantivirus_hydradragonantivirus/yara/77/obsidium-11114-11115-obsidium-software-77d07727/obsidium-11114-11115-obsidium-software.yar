import "pe"
rule _Obsidium_11114__11115__Obsidium_Software_
{
	meta:
		description = "Obsidium 1.1.1.14 - 1.1.1.15 -> Obsidium Software"
	strings:
		$0 = {EB 02 ?? ?? E8 3F 1D 00 00}
	condition:
		$0 at pe.entry_point
}