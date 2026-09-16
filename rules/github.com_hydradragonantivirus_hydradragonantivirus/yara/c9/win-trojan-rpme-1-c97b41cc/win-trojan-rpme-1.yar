rule Win_Trojan_RPME_1
{
strings:
	$a0 = { 904050bbfba9f7d353bf18fff7df57bfff5d479057bb7d11f7db53befcd1f7de56ba8c4490 }


condition:
	$a0
}