rule Win_Trojan_COMx_1
{
strings:
	$a0 = { 020e079c2eff1e0a00c3b80103bb00029c2eff1e0a00c3bf000233f6fc0e1fad3b05c3 }


condition:
	$a0
}