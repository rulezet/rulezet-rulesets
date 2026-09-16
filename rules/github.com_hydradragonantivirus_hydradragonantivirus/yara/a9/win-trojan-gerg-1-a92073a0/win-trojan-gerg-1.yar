rule Win_Trojan_Gerg_1
{
strings:
	$a0 = { 4b017317e85901b44fcd21724373d7 }


condition:
	$a0
}