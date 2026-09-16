rule Win_Trojan_Aref_2
{
strings:
	$a0 = { 99750293cf9c3d004b7561601e06b00133c9b443cd21 }


condition:
	$a0
}