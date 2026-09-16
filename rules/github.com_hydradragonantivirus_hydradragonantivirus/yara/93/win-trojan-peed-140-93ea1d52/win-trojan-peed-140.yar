rule Win_Trojan_Peed_140
{
strings:
	$a0 = { eb1550bb0000004089d0f7e3bb02000000f7e389c258c329db8b6c1c1c81ed48 }


condition:
	$a0
}