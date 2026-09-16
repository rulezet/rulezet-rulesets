rule Win_Trojan_EraseBoot_1
{
strings:
	$a0 = { 51525083f802720383c0789233c0cd13720958b9010033d2cd2650585a59c3 }


condition:
	$a0
}