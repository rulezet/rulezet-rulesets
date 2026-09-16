rule Win_Trojan_Kot_4
{
strings:
	$a0 = { 33f6b995018a9c????26881c46e2f650b8340050cb }


condition:
	$a0
}