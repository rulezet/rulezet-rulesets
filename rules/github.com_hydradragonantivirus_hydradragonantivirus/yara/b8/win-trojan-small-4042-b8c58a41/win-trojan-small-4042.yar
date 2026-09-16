rule Win_Trojan_Small_4042
{
strings:
	$a0 = { ba00????005289d181c1fc040000e815000000056636f7ff3102c1020383c212 }


condition:
	$a0
}