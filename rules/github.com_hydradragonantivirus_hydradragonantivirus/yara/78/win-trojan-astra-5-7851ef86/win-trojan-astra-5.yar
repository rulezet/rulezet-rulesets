rule Win_Trojan_Astra_5
{
strings:
	$a0 = { ff1380a2007006434f4e20202020202b06de00de00d80000028202de00c602de02de02de00de00413704423f04 }


condition:
	$a0
}