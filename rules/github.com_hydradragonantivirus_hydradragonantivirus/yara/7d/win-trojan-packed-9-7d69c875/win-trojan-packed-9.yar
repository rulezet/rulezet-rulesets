rule Win_Trojan_Packed_9
{
strings:
	$a0 = { e8000000005b83eb05eb04524e442185 }


condition:
	$a0
}