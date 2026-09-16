rule Win_Trojan_Nightmare_1
{
strings:
	$a0 = { 7c03ff348f06e8fdb41a0e1fbaf4fbcd212bc08ed8be90000e07bf7e03b90400a4e2fdbe9000c70462038c4c02 }


condition:
	$a0
}