rule Win_Trojan_NMSG_1
{
strings:
	$a0 = { 7865003c3c4e4d53473e3e5d1e068cd080c4108b1e020029c380ff1072478ec033d2161fb4 }


condition:
	$a0
}