rule Win_Trojan_EraseHDD_9
{
strings:
	$a0 = { b90100ba8000b8ff03cd13fec6ebf7 }


condition:
	$a0
}