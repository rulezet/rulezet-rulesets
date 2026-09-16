rule Win_Trojan_Wtfm_1
{
strings:
	$a0 = { c35fb4e780c4b832254757ebf12bf681c6ea4181f6704133c981f11601390c7232b8a55505bd }


condition:
	$a0
}