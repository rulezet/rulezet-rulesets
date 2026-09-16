rule Win_Trojan_Kode_10
{
strings:
	$a0 = { 568b7401813e82002f3f7503e9c500bf500203fe8b058a4d02bf00018905884d02b44eba080203d6cd217303 }


condition:
	$a0
}