rule Win_Trojan_Gergana_7
{
strings:
	$a0 = { 8d0150ba80ffb41acd21ba2902b824 }


condition:
	$a0
}