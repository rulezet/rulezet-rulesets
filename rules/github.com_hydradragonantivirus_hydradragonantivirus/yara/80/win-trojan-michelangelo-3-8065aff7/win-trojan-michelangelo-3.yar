rule Win_Trojan_Michelangelo_3
{
strings:
	$a0 = { be007c33fffcf3a42eff2e037c33c08e }


condition:
	$a0
}