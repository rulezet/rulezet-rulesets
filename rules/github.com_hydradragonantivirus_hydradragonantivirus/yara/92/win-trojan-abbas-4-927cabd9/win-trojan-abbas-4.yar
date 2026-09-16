rule Win_Trojan_Abbas_4
{
strings:
	$a0 = { ff1e0a00c38b1e7901b43f9c2eff1e0a00c3b4439c2eff1e0a00c38b1e7901b4409c2eff1e0a00 }


condition:
	$a0
}