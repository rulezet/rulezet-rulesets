rule Win_Trojan_Gen_142
{
strings:
	$a0 = { ce019a0d0042015589e5b800029acd02ce0181ec0002bf95130e57bfee011e57b8ff00509a6c0bce018dbe00fe }


condition:
	$a0
}