rule Win_Trojan_ASBV_1
{
strings:
	$a0 = { a30c7da14e00a30e7dbb4c008b87c703488987c703c1e006894702c7077301a32600c70624 }


condition:
	$a0
}