import "pe"
rule _y0das_Crypter_v1x__Modified_
{
	meta:
		description = "y0da's Crypter v1.x / Modified"
	strings:
		$0 = {E9 12 ?? ?? ?? E9 FB FF FF FF C3 68 64 FF}
	condition:
		$0 at pe.entry_point
}