rule Win_Trojan_Costeau_1
{
strings:
	$a0 = { cd218bf20e1f81c6a700b92500f3a774c0b430cd21 }


condition:
	$a0
}