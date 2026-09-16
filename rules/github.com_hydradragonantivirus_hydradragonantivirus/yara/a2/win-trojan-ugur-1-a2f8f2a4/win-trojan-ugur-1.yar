rule Win_Trojan_Ugur_1
{
strings:
	$a0 = { 437505b834349dcf3d004b743680fc3b750ae9d302 }


condition:
	$a0
}