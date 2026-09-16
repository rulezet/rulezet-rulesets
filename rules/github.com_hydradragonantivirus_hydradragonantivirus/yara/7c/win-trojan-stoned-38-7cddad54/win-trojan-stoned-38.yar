rule Win_Trojan_Stoned_38
{
strings:
	$a0 = { 7c89e6501fa1130448a31304b106d3e08ec0a3667cfbfc31ffb90001f2a5ea6800c09fbe4c00 }


condition:
	$a0
}