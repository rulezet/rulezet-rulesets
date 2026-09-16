rule Win_Trojan_Packed_100
{
strings:
	$a0 = { 99229911e8d6ffffff6801000000e82effffff7423ff742404e884ffffff836c2408000f840402000060e898ffffff83e8000f85e8010000 }


condition:
	$a0
}