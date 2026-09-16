rule Win_Trojan_Kode_9
{
strings:
	$a0 = { 568b7401813e82002f3f7503e9c400bf4f0203fe8b058a4d02bf00018905884d02b44eba070203d6cd217303 }


condition:
	$a0
}