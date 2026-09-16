rule Win_Trojan_W_34
{
strings:
	$a0 = { ba0201cd218bd8b8004233c9ba3c00cd21b43fba0e01b90400cd2133ede80c01b43fba1201b90200cd21813e12 }


condition:
	$a0
}