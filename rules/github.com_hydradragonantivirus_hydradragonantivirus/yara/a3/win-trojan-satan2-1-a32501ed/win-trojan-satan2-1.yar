rule Win_Trojan_Satan2_1
{
strings:
	$a0 = { 88366c0088166d00b800428b1639008b0e3b00e80c01b440b9f80a33d2e802017219 }


condition:
	$a0
}