rule Win_Trojan_Turkish_1
{
strings:
	$a0 = { b910002a0e7001b440cd21ba0001b95c0290b440cd218b0e05018b160301b8015753cd215b }


condition:
	$a0
}