rule Win_Trojan_W95APPAR_1
{
strings:
	$a0 = { be87000033c0eb4f66813b4d5a741653e88588000057e8a787000056e8a187000033c0eb328bd3 }


condition:
	$a0
}