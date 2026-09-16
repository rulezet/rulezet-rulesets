rule Win_Trojan_Bound_2
{
strings:
	$a0 = { 6d6964286d73626f756e642c662b3129 }

	$a1 = { 646f7768696c65743e30[0-56]266d696428746d702c742b3129 }


condition:
	$a0 and $a1
}