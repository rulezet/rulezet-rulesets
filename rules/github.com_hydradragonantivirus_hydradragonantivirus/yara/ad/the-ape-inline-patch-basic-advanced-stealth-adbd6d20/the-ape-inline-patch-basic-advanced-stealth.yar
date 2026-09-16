import "pe"
rule _The_aPE_Inline_Patch_Basic_Advanced_Stealth_
{
	meta:
		description = "The aPE Inline Patch Basic, Advanced, Stealth)"
	strings:
		$0 = {B9 ?? ?? ?? 00 E8 ?? ?? 00 00 89 01 68}
	condition:
		$0 at pe.entry_point
}