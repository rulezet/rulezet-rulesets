rule Win_Trojan_Mummy_2
{
strings:
	$a0 = { 33d2b9d105b4409c2eff1ea804e8e500 }


condition:
	$a0
}