rule Win_Trojan_Hallochen_1
{
strings:
	$a0 = { c903d98ed3bcdb0853bb2e0053cb }


condition:
	$a0
}