rule Win_Trojan_ExeHeader_3
{
strings:
	$a0 = { 07354d5a741126803feb754426817f5cb40d742ee93900 }


condition:
	$a0
}