rule Win_Trojan_R_72
{
strings:
	$a0 = { 9090e80000565e5e81c62301bf0001fca5a581ee2a01e81400eb2ce80f00b440b92e018bd6cd21e80300 }


condition:
	$a0
}