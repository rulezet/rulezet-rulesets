rule Win_Trojan_Mybot_4568
{
strings:
	$a0 = { 4d6f7a6c612f34[0-35]55726c41[0-65]68746279[0-115]5f5f[0-40]4644497353????????41 }


condition:
	$a0
}