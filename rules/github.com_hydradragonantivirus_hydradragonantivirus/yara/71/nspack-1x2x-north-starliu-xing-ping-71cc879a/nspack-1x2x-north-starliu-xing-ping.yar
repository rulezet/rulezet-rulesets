import "pe"
rule _nSPack_1x2x__North_StarLiu_Xing_Ping_
{
	meta:
		description = "nSPack 1.x/2.x -> North Star/Liu Xing Ping"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8}
	condition:
		$0 at pe.entry_point
}