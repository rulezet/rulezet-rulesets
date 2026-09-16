rule Win_Trojan_Fakeav_34
{
strings:
	$a0 = { 558bec81ec0001000050515657e80d000000054beaefef740250c333c0c9c367 }


condition:
	$a0
}