rule Win_Trojan_SillyC_247
{
strings:
	$a0 = { bf0001beb107b90300f3a48bfe83ef03ba00ffb41acd21b44e33c98bd6cd2172478bf783c603ba1effb8023dcd21 }


condition:
	$a0
}