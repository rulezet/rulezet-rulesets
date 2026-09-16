rule Win_Trojan_Nazi_11
{
strings:
	$a0 = { cf163bfc7204b44ccd21be7511b929 }


condition:
	$a0
}