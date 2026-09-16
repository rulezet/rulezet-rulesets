rule Win_Trojan_Exeheader_2
{
strings:
	$a0 = { 4d5a741126803feb754426817f5cb40d742ee939002683 }


condition:
	$a0
}