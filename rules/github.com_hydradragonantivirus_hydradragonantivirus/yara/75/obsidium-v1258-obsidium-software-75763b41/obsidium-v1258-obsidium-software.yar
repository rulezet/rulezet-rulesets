import "pe"
rule _Obsidium_V1258__Obsidium_Software_
{
	meta:
		description = "Obsidium V1.2.5.8 -> Obsidium Software"
	strings:
		$0 = {EB 01 ?? E8 ?? 00 00 00}
	condition:
		$0 at pe.entry_point
}