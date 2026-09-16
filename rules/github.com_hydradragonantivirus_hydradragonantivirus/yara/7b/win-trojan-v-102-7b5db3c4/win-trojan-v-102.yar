rule Win_Trojan_V_102
{
strings:
	$a0 = { b9b301562e8104b834ade2f85805e002ffe0 }


condition:
	$a0
}