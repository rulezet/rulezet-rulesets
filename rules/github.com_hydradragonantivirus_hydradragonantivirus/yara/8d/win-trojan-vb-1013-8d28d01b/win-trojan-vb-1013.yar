rule Win_Trojan_VB_1013
{
strings:
	$a0 = { 5c006b0064006900750065003700330032002e007400780074 }

	$a1 = { 66726d506f70706572 }

	$a2 = { 4475636b79 }


condition:
	$a0 and $a1 and $a2
}