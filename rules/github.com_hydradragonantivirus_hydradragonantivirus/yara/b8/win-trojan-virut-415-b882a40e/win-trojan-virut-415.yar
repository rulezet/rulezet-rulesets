rule Win_Trojan_Virut_415
{
strings:
	$a0 = { 6a2868f8120001e87501000033ff57e92f0b0000016681384d5a751f8b483c03 }


condition:
	$a0
}