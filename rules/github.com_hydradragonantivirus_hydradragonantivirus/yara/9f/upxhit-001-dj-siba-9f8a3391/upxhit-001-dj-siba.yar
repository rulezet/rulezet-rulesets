rule _UPXHiT_001__DJ_Siba_
{
	meta:
		description = "UPX$HiT 0.0.1 -> DJ Siba"
	strings:
		$0 = {E2 FA 94 FF E0 61 00 00 00 00 00 00 00}
	condition:
		$0
}