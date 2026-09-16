rule Win_Trojan_Morgul_1
{
strings:
	$a0 = { ffcd213d6b4f743a33c08ec026a18400268b1e8600bd81022e032e01012e8946002e895e02b8 }


condition:
	$a0
}