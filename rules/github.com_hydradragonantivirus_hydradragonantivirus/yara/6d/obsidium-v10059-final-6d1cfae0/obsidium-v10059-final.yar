import "pe"
rule _Obsidium_v10059_Final_
{
	meta:
		description = "Obsidium v1.0.0.59 Final"
	strings:
		$0 = {E8 AF}
	condition:
		$0 at pe.entry_point
}