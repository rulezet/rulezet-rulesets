rule Win_Trojan_U_94
{
strings:
	$a0 = { 3b7036370dc3fc76143703fa7e149b8def2807defd6ca5d506c2fa0e729b86be1736c8c2fa50728b }


condition:
	$a0
}