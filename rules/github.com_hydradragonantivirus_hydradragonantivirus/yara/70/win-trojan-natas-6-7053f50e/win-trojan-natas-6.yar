rule Win_Trojan_Natas_6
{
strings:
	$a0 = { bf0021ffc787cb47b92de281f506cc81c27501316dfe480bc08bf475e6 }


condition:
	$a0
}