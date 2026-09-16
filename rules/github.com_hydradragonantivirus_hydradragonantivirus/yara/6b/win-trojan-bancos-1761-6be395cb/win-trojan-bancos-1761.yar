rule Win_Trojan_Bancos_1761
{
strings:
	$a0 = { 6bccb33193a228f1be6fbd001589abc9bb1974604776a20d3f03116a60eaeee43471a3f0bd1a98aad760690c4e8d73754cb08dd96f1f772471f971cefe0446e1ba345d5cf787 }


condition:
	$a0
}