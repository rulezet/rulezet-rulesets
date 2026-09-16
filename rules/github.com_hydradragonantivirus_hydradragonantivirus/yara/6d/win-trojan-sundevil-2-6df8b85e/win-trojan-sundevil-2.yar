rule Win_Trojan_Sundevil_2
{
strings:
	$a0 = { dbb9010033d2cd269d0e1f8d969f00b409cd21cd05ebfce857002d00105007268b0eb102 }


condition:
	$a0
}