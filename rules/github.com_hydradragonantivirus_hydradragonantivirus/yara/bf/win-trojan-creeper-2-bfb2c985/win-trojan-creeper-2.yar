rule Win_Trojan_Creeper_2
{
strings:
	$a0 = { 0e071fc3cd20502d004b7426583dff437515a18a018bf0 }


condition:
	$a0
}