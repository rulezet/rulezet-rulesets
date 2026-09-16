rule Win_Trojan_Bancos_845
{
strings:
	$a0 = { 303334202d20436f6e746120496e76657374696d656e746f202d20502e4a7572 }


condition:
	$a0
}