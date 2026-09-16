rule Win_Trojan_Virogen_2
{
strings:
	$a0 = { fc0e741b3d004b750580fdfb7511175c071f5d5e5f5a59 }


condition:
	$a0
}