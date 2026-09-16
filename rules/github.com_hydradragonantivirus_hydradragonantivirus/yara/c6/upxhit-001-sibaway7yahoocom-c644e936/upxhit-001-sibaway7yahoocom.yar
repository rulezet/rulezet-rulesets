rule _UPXHiT_001__sibaway7yahoocom_
{
	meta:
		description = "UPX$HiT 0.0.1 -> sibaway7@yahoo.com"
	strings:
		$0 = {E2 FA 94 FF E0 61 00 00 00 00 00 00 00}
	condition:
		$0
}