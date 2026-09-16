rule Win_Trojan_Zhangpo_1
{
strings:
	$a0 = { 7a68616e67706f00582d4d61696c6572 }


condition:
	$a0
}