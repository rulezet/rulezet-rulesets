rule Win_Trojan_Peed_414
{
strings:
	$a0 = { 89c28d9417bd0c000081c22144000081fa21440000743081 }


condition:
	$a0
}