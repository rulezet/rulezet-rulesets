rule Win_Trojan_Leprmut_1
{
strings:
	$a0 = { e894000bc0740ae8550046fe068803eb08bad103b43bcd21463b3685037ce1803e88 }


condition:
	$a0
}