rule Win_Trojan_Proxy_76
{
strings:
	$a0 = { 81dbf0ad3a6703de507100b890e024b15881c7317b38d68b15082f410081d14b98ab782bc6bb35ba3a67687378e9e72bca03 }


condition:
	$a0
}