rule Win_Trojan__2094_0001_002_1
{
strings:
	$a0 = { c703b000e83effb440baef03b91a00cd21e82fff8a160800a1f30186260d0086e0a3f301a1 }


condition:
	$a0
}