rule Win_Trojan_Stardust_1
{
strings:
	$a0 = { 6d6163726f657865636d6f64652e616c776179735f }

	$a1 = { 6469616c6f675f6d6f64756c652c207374617264757374 }


condition:
	$a0 and $a1
}