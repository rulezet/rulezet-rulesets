rule Win_Trojan_KeyboardBug_1
{
strings:
	$a0 = { 532effb51b07bb0806b91201582e300143e2fa5b1fe8 }


condition:
	$a0
}