rule Win_Trojan_Natas_13
{
strings:
	$a0 = { 81d7d192bbf9ba39e201811eb781c6ffffffc3fdf9f581d1149a4321f67c0681ea942aebe4 }


condition:
	$a0
}