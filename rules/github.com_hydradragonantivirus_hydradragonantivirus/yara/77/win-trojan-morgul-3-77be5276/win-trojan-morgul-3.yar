rule Win_Trojan_Morgul_3
{
strings:
	$a0 = { ffcd213d6b4f743c0633c08ec026a18400268b1e8600bd98022e032e01012e8946002e895e02 }


condition:
	$a0
}