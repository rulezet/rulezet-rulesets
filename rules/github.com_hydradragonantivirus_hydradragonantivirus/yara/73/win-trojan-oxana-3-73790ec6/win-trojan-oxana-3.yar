rule Win_Trojan_Oxana_3
{
strings:
	$a0 = { b5827e13b700b4028a166c078a366d07cd10b409b90100b0dacd108a166c07fec2b4028a366d07cd10b409b901 }


condition:
	$a0
}