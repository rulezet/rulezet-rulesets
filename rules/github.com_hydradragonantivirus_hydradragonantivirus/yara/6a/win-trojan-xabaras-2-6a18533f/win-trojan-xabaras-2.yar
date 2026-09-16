rule Win_Trojan_Xabaras_2
{
strings:
	$a0 = { ba0001b440cd21e80100c3bbb401 }


condition:
	$a0
}