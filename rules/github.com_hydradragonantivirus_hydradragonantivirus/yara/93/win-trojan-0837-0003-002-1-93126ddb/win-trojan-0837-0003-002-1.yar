rule Win_Trojan__0837_0003_002_1
{
strings:
	$a0 = { a5017303e93f01b903008d164501b440cd21e931010e1f2e8b1e5201b80242b9ffffbafeffcd }


condition:
	$a0
}