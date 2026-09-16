rule Win_Trojan_Trivial_568
{
strings:
	$a0 = { 8bfeb159ac34??aafec980f9ff75 }


condition:
	$a0
}