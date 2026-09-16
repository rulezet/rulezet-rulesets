rule Win_Trojan_Catholic_1
{
strings:
	$a0 = { ed0300b9ffffac4975fdb9ffffac4975fd0e0e }


condition:
	$a0
}