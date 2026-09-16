rule Win_Trojan_VGEN_258
{
strings:
	$a0 = { e800005d81ed03011e0e1fb0db8dbe1901b91f0b300547e2fb564d22d933cbda63d9e616faa8e5564d04d933d9da63d9 }


condition:
	$a0
}