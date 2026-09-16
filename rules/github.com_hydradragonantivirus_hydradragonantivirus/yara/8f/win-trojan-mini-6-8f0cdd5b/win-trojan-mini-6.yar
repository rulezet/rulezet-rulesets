rule Win_Trojan_Mini_6
{
strings:
	$a0 = { 3dcd2193b6feb43fe82e00803e9efeb47411b80242e81700896d068bd7b80042e80c00b43ecd }


condition:
	$a0
}