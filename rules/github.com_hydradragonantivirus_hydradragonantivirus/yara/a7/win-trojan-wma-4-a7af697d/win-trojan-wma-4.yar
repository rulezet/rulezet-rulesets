rule Win_Trojan_WMA_4
{
strings:
	$a0 = { ecb42acd218b6efa81ed0b01eb01002e8a9e1401bf9e03908bcf8db62e012e301c46b42ecd21e0 }


condition:
	$a0
}