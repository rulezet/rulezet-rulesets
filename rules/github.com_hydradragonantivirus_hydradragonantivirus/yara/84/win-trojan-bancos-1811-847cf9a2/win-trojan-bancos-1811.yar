rule Win_Trojan_Bancos_1811
{
strings:
	$a0 = { 53af9899911ffdf149237ef278687bc0d1569b44bbb15b10f889eb6c369e33e1bc665a6cc704d85130825215c3fb45bbbf7ffae30a35fb72afea569440c563bde53cb0b74a57 }


condition:
	$a0
}