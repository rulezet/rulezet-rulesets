rule Win_Trojan_Proxy_77
{
strings:
	$a0 = { eb01b4eb013852eb02b582ba71f3c40a5a575771005f5f81d6a88c37df52eb02173a5a8b1538414100eb0265ebbb177f4aea }


condition:
	$a0
}