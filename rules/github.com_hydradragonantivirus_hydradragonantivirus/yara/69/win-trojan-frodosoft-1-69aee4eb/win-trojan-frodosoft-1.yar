rule Win_Trojan_FrodoSoft_1
{
strings:
	$a0 = { ed8d97ee01cd218b95c9018e9dcb01b82425cd210e070e }


condition:
	$a0
}