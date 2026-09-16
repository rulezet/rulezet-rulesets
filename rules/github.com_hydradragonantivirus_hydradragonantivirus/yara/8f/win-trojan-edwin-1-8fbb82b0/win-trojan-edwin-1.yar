rule Win_Trojan_Edwin_1
{
strings:
	$a0 = { 1f6800000730e4cd1372fa8b1e017c803e007ceb750330ff4b81c3a80081eb5b00ffb7027c }


condition:
	$a0
}