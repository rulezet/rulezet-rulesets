rule Win_Trojan_U_27
{
strings:
	$a0 = { 484f4d453d25730043616e277420666f726b207074792c2062796521 }


condition:
	$a0
}