rule Win_Trojan_Chameleon_6
{
strings:
	$a0 = { ff008b4ee881c1270003ca8bd681eacd05cd219c508b4ee88b46ea8bfe81efa605e80300589dc3 }


condition:
	$a0
}