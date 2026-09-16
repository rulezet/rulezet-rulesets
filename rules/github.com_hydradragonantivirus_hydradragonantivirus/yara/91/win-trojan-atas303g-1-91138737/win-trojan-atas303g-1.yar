rule Win_Trojan_Atas303G_1
{
strings:
	$a0 = { 8d7c4afec23015300d47e2f7c3 }


condition:
	$a0
}