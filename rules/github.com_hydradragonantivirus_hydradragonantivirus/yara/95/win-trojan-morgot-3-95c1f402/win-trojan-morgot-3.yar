rule Win_Trojan_Morgot_3
{
strings:
	$a0 = { 8b1ed903b440e989feb91c00bab3038b1ed903b440e97afeb91c00bab3038b1ed903b43fe9 }


condition:
	$a0
}