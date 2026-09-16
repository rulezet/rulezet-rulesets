import "pe"
rule _Obsidium_unknown_version_
{
	meta:
		description = "Obsidium unknown version"
	strings:
		$0 = {EB 01 ?? 50 EB 03 ?? ?? ?? E8 ?? 00 00 00 EB 03}
	condition:
		$0 at pe.entry_point
}