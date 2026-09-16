rule Win_Trojan_AmbulanceCar_1
{
strings:
	$a0 = { f0ffba0000b91000e83f0042e2fae81600e87b00 }


condition:
	$a0
}