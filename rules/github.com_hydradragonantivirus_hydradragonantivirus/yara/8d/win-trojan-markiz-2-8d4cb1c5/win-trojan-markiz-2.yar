rule Win_Trojan_Markiz_2
{
strings:
	$a0 = { a324e8bd209e729452bfe824a34ea1aa9a1341acf9ff11a49014fafc3f7faea317fe65e49ab915c2 }


condition:
	$a0
}