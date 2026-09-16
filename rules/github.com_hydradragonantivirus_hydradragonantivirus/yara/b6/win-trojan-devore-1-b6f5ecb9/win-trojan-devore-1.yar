rule Win_Trojan_Devore_1
{
strings:
	$a0 = { 8b5d0157be490203f3b90300f3a4ba750203d3b41acd21bff50203fbc60500be4c0203f3bff90203fbb906008a }


condition:
	$a0
}