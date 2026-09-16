rule Win_Trojan_ChineseFish_1
{
strings:
	$a0 = { 1e561653bf2b7cb90b00fcac26803d007400268a058a }


condition:
	$a0
}