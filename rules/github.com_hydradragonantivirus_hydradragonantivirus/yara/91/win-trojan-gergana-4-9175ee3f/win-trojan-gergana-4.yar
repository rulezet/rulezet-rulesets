rule Win_Trojan_Gergana_4
{
strings:
	$a0 = { 4c0150ba80ffb41acd21b92000ba46 }


condition:
	$a0
}