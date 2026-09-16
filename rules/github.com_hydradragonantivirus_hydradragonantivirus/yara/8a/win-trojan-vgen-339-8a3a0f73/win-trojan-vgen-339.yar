rule Win_Trojan_VGEN_339
{
strings:
	$a0 = { 060e1ffafce870ffa0af01fec07458e8b8007553e85300740be874007406e87c007401c3e886ffb84200e83bff03e8 }


condition:
	$a0
}