rule Win_Trojan_E_6
{
strings:
	$a0 = { 0e0e1f07bf2400e80400e91600048a260e00be2400b9dc00ac32c4aae2fac3 }


condition:
	$a0
}