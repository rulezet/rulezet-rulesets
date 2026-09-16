rule Win_Trojan_Tero_1
{
strings:
	$a0 = { 04cd16e80000598be981ed0b01e81a00eb2b3e37e81300b925018d960301e80400e80600c3b4 }


condition:
	$a0
}