rule Win_Trojan_Cara_2
{
strings:
	$a0 = { fe00b80143cd62b8023dcd62721a8b }


condition:
	$a0
}