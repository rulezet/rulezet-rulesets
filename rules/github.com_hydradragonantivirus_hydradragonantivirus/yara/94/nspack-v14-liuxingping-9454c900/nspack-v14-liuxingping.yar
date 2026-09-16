import "pe"
rule _NsPack_V14__LiuXingPing_
{
	meta:
		description = "NsPack V1.4 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00}
	condition:
		$0 at pe.entry_point
}