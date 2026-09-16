rule Win_Trojan_Hiroshima_1
{
strings:
	$a0 = { 1e060e8cc8e800005bb104d3eb03c35050558becc746021c005dcb0e1f0e078f06fa02fbe80700071f2eff2ef802b4 }


condition:
	$a0
}