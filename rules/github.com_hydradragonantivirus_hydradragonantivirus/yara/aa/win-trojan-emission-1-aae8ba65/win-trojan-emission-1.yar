rule Win_Trojan_Emission_1
{
strings:
	$a0 = { 01010055e015000000ffff000000003504000008000000ee0b }


condition:
	$a0
}