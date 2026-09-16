rule Win_Trojan_LostHorizons_1
{
strings:
	$a0 = { 929292929292e800005d81ed0b018bc5051a0150eb16eb260000e80f00b440b9bf028d960001cd21e80100c38b86 }


condition:
	$a0
}