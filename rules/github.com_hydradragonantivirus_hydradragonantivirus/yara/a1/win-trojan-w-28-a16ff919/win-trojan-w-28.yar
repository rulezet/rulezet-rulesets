rule Win_Trojan_W_28
{
strings:
	$a0 = { b86ec03a552633dc339e0057aa5312c46a1df28d87defebf87a0febf5520329d339e306b9ef88c1f }


condition:
	$a0
}