rule Win_Trojan_Markus_2
{
strings:
	$a0 = { 8f73839abbfce35928333010168db1dbd6cbfbdaeb1fffa7f46bf85a2e6bc663077e14a33e78abc1 }


condition:
	$a0
}