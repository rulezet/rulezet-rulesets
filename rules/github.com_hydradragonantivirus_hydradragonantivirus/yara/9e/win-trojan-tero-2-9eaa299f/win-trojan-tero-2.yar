rule Win_Trojan_Tero_2
{
strings:
	$a0 = { cd16e80000598be981ed0b01e81a00eb2b3725e81300b934018d960301e80400e80600c3b440cd21c38b861701 }


condition:
	$a0
}