rule Win_Trojan_Jak_8
{
strings:
	$a0 = { e800005d81ed0300e80200eb12b925008d9e????8b96????31174343e2fac3 }


condition:
	$a0
}