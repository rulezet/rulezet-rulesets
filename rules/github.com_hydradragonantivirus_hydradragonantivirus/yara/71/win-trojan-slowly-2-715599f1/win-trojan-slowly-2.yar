rule Win_Trojan_Slowly_2
{
strings:
	$a0 = { b9300166ad66f7d866abe2f7c3 }


condition:
	$a0
}