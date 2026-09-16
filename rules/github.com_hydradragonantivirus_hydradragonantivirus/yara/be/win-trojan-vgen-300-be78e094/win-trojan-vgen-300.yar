rule Win_Trojan_VGEN_300
{
strings:
	$a0 = { 5bb801faba4559cd16e800005d81ed1201e8f600eb01908db6b801bf0001a5a50e1f8d961102b41acd21b8013580ec }


condition:
	$a0
}