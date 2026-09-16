rule Win_Trojan_Krile_8
{
strings:
	$a0 = { c7ad3c5a4d846b47e574ef0f7b8b76d34ab88cd3153375813ee80f009ae8f9ff9a9ceb019a }


condition:
	$a0
}