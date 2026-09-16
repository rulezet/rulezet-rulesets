rule Win_Trojan_LBBCV_1
{
strings:
	$a0 = { c08ed8be4c00bf0070a5a5b80470bb4c0089078cc0894702 }


condition:
	$a0
}