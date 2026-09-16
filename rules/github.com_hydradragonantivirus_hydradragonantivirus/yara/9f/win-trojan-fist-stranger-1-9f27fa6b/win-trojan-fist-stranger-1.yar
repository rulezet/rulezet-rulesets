rule Win_Trojan_Fist_stranger_1
{
strings:
	$a0 = { 935d8bf556b030b9af02482e300446e2f9c3 }


condition:
	$a0
}