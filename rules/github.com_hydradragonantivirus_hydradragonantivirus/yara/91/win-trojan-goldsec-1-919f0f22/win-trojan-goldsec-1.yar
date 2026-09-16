rule Win_Trojan_Goldsec_1
{
strings:
	$a0 = { 010300559e01000300ffff000000005b060000090000000103 }


condition:
	$a0
}