rule Win_Trojan_Winspy_8
{
strings:
	$a0 = { bc7f4000e87f4000f47f4000a49d4000d8814000ec814000 }


condition:
	$a0
}