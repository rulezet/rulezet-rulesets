rule Win_Trojan_Zherkov_8
{
strings:
	$a0 = { c61890b9d9062e3004fec046e2f8 }


condition:
	$a0
}