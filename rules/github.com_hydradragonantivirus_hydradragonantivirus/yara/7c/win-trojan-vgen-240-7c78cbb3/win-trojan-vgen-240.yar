rule Win_Trojan_VGEN_240
{
strings:
	$a0 = { 07019a0d0089005589e5b802029acd02070181ec0202e82afcbf79070e57e80efabf81070e57e806fabf8b070e }


condition:
	$a0
}