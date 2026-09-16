rule Win_Trojan_WIRE3518_1
{
strings:
	$a0 = { dbfabc007c8ed3fb903683af130404b106cd12d3e0ba80005050b90b00b8070207cd13b8d30050cb }


condition:
	$a0
}