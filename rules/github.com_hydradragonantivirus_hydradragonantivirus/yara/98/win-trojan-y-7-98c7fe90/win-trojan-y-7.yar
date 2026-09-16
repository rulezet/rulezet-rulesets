rule Win_Trojan_Y_7
{
strings:
	$a0 = { be16018bfefcb432b2ddcd2186c1ac3400aae2fa }


condition:
	$a0
}