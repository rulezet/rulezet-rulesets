rule Win_Trojan_Vandor_1
{
strings:
	$a0 = { 0d01b9f303300446e2fb6d95d55b15f375b9d5dbd277d4d42bd32bd185f1d2053505356b1ed1d6257876ddd478 }


condition:
	$a0
}