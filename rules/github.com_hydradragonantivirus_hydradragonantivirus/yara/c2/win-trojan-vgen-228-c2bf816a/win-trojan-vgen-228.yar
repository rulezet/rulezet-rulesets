rule Win_Trojan_VGEN_228
{
strings:
	$a0 = { 018b6e008ba602008b9e0400b44acd21a12c00898618008b9e0000ffe3f0013801860153e800005b8bfe4f1eff57 }


condition:
	$a0
}