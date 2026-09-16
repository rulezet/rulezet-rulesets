rule Win_Trojan_Monster_50
{
strings:
	$a0 = { b42fcd21891e????8c06????0e07bad302b41acd21eb1b }


condition:
	$a0
}