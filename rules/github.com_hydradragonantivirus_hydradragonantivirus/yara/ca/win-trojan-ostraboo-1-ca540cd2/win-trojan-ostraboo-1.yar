rule Win_Trojan_Ostraboo_1
{
strings:
	$a0 = { 81f33dab8785475d35acea2db8e886c435a50286e08785475d83effeeb01a04b7402ebe00e }


condition:
	$a0
}