rule Win_Trojan_Mummy_1
{
strings:
	$a0 = { d2b97705b4409c2eff1e0f00e87000 }


condition:
	$a0
}