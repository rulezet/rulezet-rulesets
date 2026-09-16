rule Win_Trojan_Lamza_2
{
strings:
	$a0 = { 68fe234000e8affcffffc9c20400 }


condition:
	$a0
}