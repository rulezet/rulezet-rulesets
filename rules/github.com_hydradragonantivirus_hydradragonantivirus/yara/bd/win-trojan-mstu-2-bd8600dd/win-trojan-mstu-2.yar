rule Win_Trojan_MSTU_2
{
strings:
	$a0 = { bb1600268b073deb55c35e8bc6b104d3 }


condition:
	$a0
}