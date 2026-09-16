import "pe"
rule _y0das_Crypter_v12_
{
	meta:
		description = "y0da's Crypter v1.2"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED B9 ?? ?? 8D BD 8B F7}
	condition:
		$0 at pe.entry_point
}