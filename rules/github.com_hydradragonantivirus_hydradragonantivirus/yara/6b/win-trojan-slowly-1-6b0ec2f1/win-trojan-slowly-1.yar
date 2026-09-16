rule Win_Trojan_Slowly_1
{
strings:
	$a0 = { 56bf????b9290051f3a468????b9b50166ad66f7d866abe2f7c3 }


condition:
	$a0
}