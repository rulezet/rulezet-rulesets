rule Win_Trojan_Gergana_10
{
strings:
	$a0 = { a1910150ba80ffb41acd21babf02b824 }


condition:
	$a0
}