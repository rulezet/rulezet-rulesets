rule Win_Trojan_Darkray_1
{
strings:
	$a0 = { 1f8bf5b95501813431de4646e2f8c3c606df06c3b9f505ba00019c }


condition:
	$a0
}