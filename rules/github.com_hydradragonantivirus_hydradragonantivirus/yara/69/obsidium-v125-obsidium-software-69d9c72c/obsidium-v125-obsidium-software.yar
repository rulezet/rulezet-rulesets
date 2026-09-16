import "pe"
rule _Obsidium_V125__Obsidium_Software_
{
	meta:
		description = "Obsidium V1.25 -> Obsidium Software"
	strings:
		$0 = {E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3}
	condition:
		$0 at pe.entry_point
}