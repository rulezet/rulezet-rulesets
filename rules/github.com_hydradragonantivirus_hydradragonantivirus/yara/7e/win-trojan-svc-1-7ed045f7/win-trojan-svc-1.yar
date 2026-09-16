rule Win_Trojan_SVC_1
{
strings:
	$a0 = { 89a4cd002e8c94cb008cc8fa8bee81c596148be58ed0fb065633d2b4ffcd2181fa02ff741f060e }


condition:
	$a0
}