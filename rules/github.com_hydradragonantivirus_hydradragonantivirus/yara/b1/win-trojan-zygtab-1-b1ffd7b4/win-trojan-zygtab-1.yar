rule Win_Trojan_Zygtab_1
{
strings:
	$a0 = { 687a676d7a7940736f68752e636f6d004a50 }


condition:
	$a0
}