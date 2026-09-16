rule Win_Trojan_Peed_248
{
strings:
	$a0 = { 558bec83ec10535657f7dbf7d885dd6a00ff1500 }


condition:
	$a0
}