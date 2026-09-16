rule Win_Trojan_Bancos_1765
{
strings:
	$a0 = { 6841d5e4ce7a3ff3ec1de7d955b7b61dfcad089f7f98becdb715afcf4d7b72d98084fc4a3a1fab1f71033e235d0690ded61b7b789c79bc5258a94ac2cb47bf2944b92995529a }


condition:
	$a0
}