rule Win_Trojan_Angel_2_1
{
strings:
	$a0 = { 23bb20282e00272e32274381fb1b2e75f3e9edfeea }


condition:
	$a0
}