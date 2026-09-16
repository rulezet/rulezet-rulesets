rule Win_Trojan_Bancos_874
{
strings:
	$a0 = { 54f696bf74308f95e95fd8d0a510fc15f0c1c0b1b177606d5aebafa0affc3ad136c4348aba1ac5c9c3c8cc386bdd8a4d5e42152414a4bccd55f8df70010da02dec }


condition:
	$a0
}