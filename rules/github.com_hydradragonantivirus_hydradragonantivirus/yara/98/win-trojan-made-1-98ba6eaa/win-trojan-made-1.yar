rule Win_Trojan_Made_1
{
strings:
	$a0 = { 8d9c49018b941701b9bc008b0733c286e033c286e0890783c302e2ef5bc3e8deffb440b900018d }


condition:
	$a0
}