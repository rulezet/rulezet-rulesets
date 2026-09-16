import "pe"
rule _beria_v007_public_WIP__symbiont_
{
	meta:
		description = "beria v0.07 public WIP --> symbiont"
	strings:
		$0 = {83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0}
	condition:
		$0 at pe.entry_point
}