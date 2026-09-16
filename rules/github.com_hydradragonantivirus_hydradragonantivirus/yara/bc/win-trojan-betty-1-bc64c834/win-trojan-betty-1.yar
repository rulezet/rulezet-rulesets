rule Win_Trojan_Betty_1
{
strings:
	$a0 = { 14201e57bf54001e57b8881350bf96201e579ac00561009a91026100bf1420 }


condition:
	$a0
}