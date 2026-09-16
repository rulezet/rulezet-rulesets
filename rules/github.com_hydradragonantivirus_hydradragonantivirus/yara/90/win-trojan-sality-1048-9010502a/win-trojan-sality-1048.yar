rule Win_Trojan_Sality_1048
{
strings:
	$a0 = { 8a44050089e4300780e90189ff5e4e0f84??000000 }


condition:
	$a0
}