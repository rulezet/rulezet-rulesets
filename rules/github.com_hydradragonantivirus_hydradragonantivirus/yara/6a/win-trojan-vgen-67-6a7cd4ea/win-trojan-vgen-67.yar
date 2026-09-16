rule Win_Trojan_VGEN_67
{
strings:
	$a0 = { b801faba4559cd16e800005d81ed1301eb0390cd208db6da01bf0001a5a50e1f8d965302b41acd21b801352d0010 }


condition:
	$a0
}