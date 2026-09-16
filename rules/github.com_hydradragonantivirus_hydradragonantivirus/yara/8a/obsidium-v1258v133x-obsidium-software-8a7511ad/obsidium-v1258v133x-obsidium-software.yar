import "pe"
rule _Obsidium_V1258V133X__Obsidium_Software_
{
	meta:
		description = "Obsidium V1.2.5.8-V1.3.3.X -> Obsidium Software"
	strings:
		$0 = {EB 01 ?? E8 ?? 00 00 00 EB 02 ?? ?? EB}
	condition:
		$0 at pe.entry_point
}