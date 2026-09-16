rule Win_Trojan_Gen_119
{
strings:
	$a0 = { e8ac02e87101e89e01e85502a12c008e }


condition:
	$a0
}