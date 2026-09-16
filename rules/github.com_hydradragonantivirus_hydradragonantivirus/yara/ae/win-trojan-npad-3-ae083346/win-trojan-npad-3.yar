rule Win_Trojan_Npad_3
{
strings:
	$a0 = { 4d414356495224000006 }


condition:
	$a0
}