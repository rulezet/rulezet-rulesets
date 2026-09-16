rule Win_Trojan_ASP_31
{
strings:
	$a0 = { 282270617373776f726422293c3e223737353835323122[0-22]beafb8e63ad0a1d1f97ec4e3cfebb8c9c2efa3 }


condition:
	$a0
}