rule Win_Trojan_GV_2
{
strings:
	$a0 = { e9771f2d0300a3840bb440ba0001b9310be87303e86401b440ba830bb90600e86503 }


condition:
	$a0
}