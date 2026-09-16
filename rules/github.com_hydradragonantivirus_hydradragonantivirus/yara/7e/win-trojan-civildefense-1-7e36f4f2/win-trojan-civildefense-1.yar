rule Win_Trojan_Civildefense_1
{
strings:
	$a0 = { bba400b9b4068a07d0c832c3041bd0c0d0c0880743e2ef1f595b58c3 }


condition:
	$a0
}