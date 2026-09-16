rule Win_Trojan_Remor_9
{
strings:
	$a0 = { 10e770ba2504b409cd21b408cd21b0fee664ba13048a268004b107cd217303e9af018b1648048b }


condition:
	$a0
}