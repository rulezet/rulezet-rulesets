rule Win_Trojan_Dewdz_1
{
strings:
	$a0 = { 4b7409b44fcd2172ba4b75f7b42fcd }


condition:
	$a0
}