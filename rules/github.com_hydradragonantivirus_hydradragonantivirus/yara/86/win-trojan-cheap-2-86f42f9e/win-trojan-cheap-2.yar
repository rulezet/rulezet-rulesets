rule Win_Trojan_Cheap_2
{
strings:
	$a0 = { 81ed08012e8a9640048db62701b919032e281446e2fa }


condition:
	$a0
}