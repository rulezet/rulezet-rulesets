rule Win_Trojan_Gen_116
{
strings:
	$a0 = { 74128cc8b10fd3e03d00807407ba }


condition:
	$a0
}