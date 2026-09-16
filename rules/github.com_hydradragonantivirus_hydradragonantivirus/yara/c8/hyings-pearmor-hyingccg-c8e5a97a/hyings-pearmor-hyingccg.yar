import "pe"
rule _hyings_PEArmor__hyingCCG_
{
	meta:
		description = "hying's PE-Armor -> hying[CCG"
	strings:
		$0 = {E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D}
	condition:
		$0 at pe.entry_point
}