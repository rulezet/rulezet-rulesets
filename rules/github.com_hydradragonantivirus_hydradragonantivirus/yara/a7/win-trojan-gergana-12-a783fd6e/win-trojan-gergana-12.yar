rule Win_Trojan_Gergana_12
{
strings:
	$a0 = { 0150c7062c020000ba80ffb41acd }


condition:
	$a0
}