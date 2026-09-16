rule Win_Trojan_Bubble_1
{
strings:
	$a0 = { 06b703e9a3b803b440b9d701bae001cd2133ed26896d1526896d17b440b90300bab303cd21 }


condition:
	$a0
}