rule Win_Trojan_SeventhSon350_1
{
strings:
	$a0 = { 1f5ab82425cd215ab80133cd210e0e1f07b8000150c3 }


condition:
	$a0
}