rule Win_Trojan_Foxi_1
{
strings:
	$a0 = { 555d81ed0601c686110101e83f038db65e03bf00018bd89357a5a48bfd8bec81ec8000b42fcd2153b41a8d56808bd8 }


condition:
	$a0
}