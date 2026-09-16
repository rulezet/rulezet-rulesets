rule Win_Trojan_Australian_10
{
strings:
	$a0 = { 8df9c2f9def9ea8e283e7a8873dac672cac903e970f0f27c8a71efcb07e9f408222a3371c9c86c24 }


condition:
	$a0
}