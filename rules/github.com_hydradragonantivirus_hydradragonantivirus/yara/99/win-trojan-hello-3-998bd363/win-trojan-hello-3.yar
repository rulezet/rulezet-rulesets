rule Win_Trojan_Hello_3
{
strings:
	$a0 = { 5d81ed07018db62501e80200eb108b962403b9ff01 }


condition:
	$a0
}