rule Win_Trojan_Istbar_232
{
strings:
	$a0 = { 0a546578743d616e6420696e7374616c6c696e672049535420746f6f6c6261 }


condition:
	$a0
}