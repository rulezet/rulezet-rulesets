rule Win_Trojan_QQPass_32
{
strings:
	$a0 = { 747168d44b400053e8cbf3ffff89c668e04b400053e8bef3ffff89c785f6745385ff744f }


condition:
	$a0
}