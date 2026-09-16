rule Win_Spyware_Zbot_1292
{
strings:
	$a0 = { f7db558bec83c4 }


condition:
	$a0
}