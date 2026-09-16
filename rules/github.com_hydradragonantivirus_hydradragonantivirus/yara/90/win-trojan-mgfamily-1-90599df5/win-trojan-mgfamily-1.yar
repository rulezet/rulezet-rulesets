rule Win_Trojan_MGFamily_1
{
strings:
	$a0 = { 07585e1ebb000153cb3d044874ff4c46ffc43e0600b0ea49f2ae26c43d83efdfea }


condition:
	$a0
}