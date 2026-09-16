import "pe"
rule _CrunchPE__BitArts_
{
	meta:
		description = "Crunch/PE -> BitArts"
	strings:
		$0 = {55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85}
	condition:
		$0 at pe.entry_point
}