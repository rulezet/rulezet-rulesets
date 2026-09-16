rule Win_Trojan_Trojan_259
{
strings:
	$a0 = { fcc07505b834129dcf80fcc1751758 }


condition:
	$a0
}