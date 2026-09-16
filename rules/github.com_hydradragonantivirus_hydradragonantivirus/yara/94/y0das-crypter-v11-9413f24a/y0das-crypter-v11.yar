import "pe"
rule _y0das_Crypter_v11_
{
	meta:
		description = "y0da's Crypter v1.1"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED F3 1D 40 ?? B9 7B 09 ?? ?? 8D BD 3B 1E 40 ?? 8B F7}
	condition:
		$0 at pe.entry_point
}