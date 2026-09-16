rule Win_Trojan_Tiny_32
{
strings:
	$a0 = { 400e1fb179cdd6b440061f59cdd6b43ecdd6071f61ea }


condition:
	$a0
}