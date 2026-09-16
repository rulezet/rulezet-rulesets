rule Win_Trojan_Saddamme_1
{
strings:
	$a0 = { 0b0e00526561647920746f20676f2e2e2e00121600ff03b70000000c04 }


condition:
	$a0
}