rule Win_Trojan_Wuwo_1
{
strings:
	$a0 = { 5168000a00008d95f0e9ffff52ff15e4704000 }


condition:
	$a0
}