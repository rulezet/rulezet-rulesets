import "pe"
rule __v10__LiJianjun_
{
	meta:
		description = "v1.0 -> Li-Jianjun"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44}
	condition:
		$0 at pe.entry_point
}