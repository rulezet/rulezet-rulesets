rule Win_Trojan_B_38
{
strings:
	$a0 = { 06e800005d81ed0b0133c08ec0bf0600abbf0e00abe4213402e6213402e6210e1f8d96a305b41acd213ec686860500 }


condition:
	$a0
}