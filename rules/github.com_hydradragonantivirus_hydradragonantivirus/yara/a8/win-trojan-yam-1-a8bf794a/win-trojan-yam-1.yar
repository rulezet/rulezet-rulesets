rule Win_Trojan_YAM_1
{
strings:
	$a0 = { 2e8a2480f4aa2e882446e2f458c3b842f2cd2181fb2f24 }


condition:
	$a0
}