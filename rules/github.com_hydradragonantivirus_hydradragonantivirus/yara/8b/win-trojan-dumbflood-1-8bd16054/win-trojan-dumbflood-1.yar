rule Win_Trojan_Dumbflood_1
{
strings:
	$a0 = { 3c40ffff5be85639faff0000ffffffff160000004d656761204368617420466c6f6f }


condition:
	$a0
}