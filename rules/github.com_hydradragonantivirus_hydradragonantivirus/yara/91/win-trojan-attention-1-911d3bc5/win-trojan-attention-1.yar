rule Win_Trojan_Attention_1
{
strings:
	$a0 = { b0008bdab501433a0775fb4b4b81275f }


condition:
	$a0
}