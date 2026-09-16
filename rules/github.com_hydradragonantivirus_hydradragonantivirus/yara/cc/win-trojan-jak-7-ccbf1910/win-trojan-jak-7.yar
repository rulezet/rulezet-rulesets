rule Win_Trojan_Jak_7
{
strings:
	$a0 = { 1a8d96a300cd21b80000cd1a8996a100e82900cd202a2e636f6d005b4a614b2e43727970745d00 }


condition:
	$a0
}