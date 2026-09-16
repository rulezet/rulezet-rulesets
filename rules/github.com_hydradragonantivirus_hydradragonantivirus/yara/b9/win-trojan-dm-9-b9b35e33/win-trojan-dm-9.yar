rule Win_Trojan_DM_9
{
strings:
	$a0 = { fe03f5bf0002b97b01f3a4061fbe }


condition:
	$a0
}