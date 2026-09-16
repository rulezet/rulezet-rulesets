rule Win_Trojan_Philis_183
{
strings:
	$a0 = { 81c78336e0695481ef8336e069 }


condition:
	$a0
}