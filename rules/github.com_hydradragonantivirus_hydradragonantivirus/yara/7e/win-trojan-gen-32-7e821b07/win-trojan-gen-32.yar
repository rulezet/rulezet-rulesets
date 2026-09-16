rule Win_Trojan_Gen_32
{
strings:
	$a0 = { 0242e88c00b440b92b0490ba0001cd217214 }


condition:
	$a0
}