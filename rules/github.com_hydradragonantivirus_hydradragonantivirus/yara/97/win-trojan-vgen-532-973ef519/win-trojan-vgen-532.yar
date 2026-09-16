rule Win_Trojan_VGEN_532
{
strings:
	$a0 = { 528bf281ee0301c35eeb2d90b42fcd218c841603899c180333d28bd681c2ea0181c200100e1fb41acd2189941403c3 }


condition:
	$a0
}