rule Win_Trojan_Gen_122
{
strings:
	$a0 = { 1e57e818fe08c07403e9fe00803e410043752d803e }


condition:
	$a0
}