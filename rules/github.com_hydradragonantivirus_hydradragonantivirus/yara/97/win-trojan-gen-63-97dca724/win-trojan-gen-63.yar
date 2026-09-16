rule Win_Trojan_Gen_63
{
strings:
	$a0 = { c033ff33c0b9ff7ffcf2ae26f605ff75f883c7038bd72e }


condition:
	$a0
}