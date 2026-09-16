rule Win_Trojan_Philis_127
{
strings:
	$a0 = { 50e800000000585860434be8 }


condition:
	$a0
}