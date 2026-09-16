rule Win_Trojan_VGEN_377
{
strings:
	$a0 = { 1e8becb42acd218b6efa81ed0b01eb01002e8a9e1401bfaf038bcf8db62d012e301c46b42ecd21e0f6061e33c05050 }


condition:
	$a0
}