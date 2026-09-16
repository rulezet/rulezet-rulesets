rule Win_Trojan_Kylie_1
{
strings:
	$a0 = { fec3e46124fce661c3535743438b3e }


condition:
	$a0
}