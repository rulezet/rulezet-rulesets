rule Win_Trojan_Small_4252
{
strings:
	$a0 = { 60e8000000005b6629 }


condition:
	$a0
}