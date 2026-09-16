rule Win_Trojan_VGEN_37
{
strings:
	$a0 = { e800005e81ee43008bfe83e7f08bc7b104d3e88cc903c150b8630050b9d808fcf3a4cb0e1fbe060033ff2e803e060000 }


condition:
	$a0
}