rule Win_Trojan_VGEN_215
{
strings:
	$a0 = { b9b2002eac34b22e8844ffe2f6fcf949ac81443c6c0cdeb638b688b6c64ead0c22ae0bd0ba9c1e86ee9c3af64d }


condition:
	$a0
}