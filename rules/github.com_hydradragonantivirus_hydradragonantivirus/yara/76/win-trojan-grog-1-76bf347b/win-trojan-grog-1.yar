rule Win_Trojan_Grog_1
{
strings:
	$a0 = { be1201b99e04ac474704??8844ff4747e2f4 }


condition:
	$a0
}