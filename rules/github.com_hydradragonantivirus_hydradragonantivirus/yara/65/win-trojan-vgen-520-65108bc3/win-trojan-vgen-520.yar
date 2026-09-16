rule Win_Trojan_VGEN_520
{
strings:
	$a0 = { bf00018bf283c609b90300f3a4528bc2052a0050c32e9c589eb4097227b42fcd218bfa2e895d0c81c28201b41acd21 }


condition:
	$a0
}