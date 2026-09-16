rule Win_Trojan_Gen_75
{
strings:
	$a0 = { e80000565e5e81c62101bf0001fca5a581ee2801e81400eb2ce80f00b440b92c018bd6cd21e80300 }


condition:
	$a0
}