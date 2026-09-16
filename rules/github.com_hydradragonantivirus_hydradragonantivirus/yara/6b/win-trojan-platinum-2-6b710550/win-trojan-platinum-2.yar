rule Win_Trojan_Platinum_2
{
strings:
	$a0 = { 7213e8f50033d2b9d105b4409c2eff1e }


condition:
	$a0
}