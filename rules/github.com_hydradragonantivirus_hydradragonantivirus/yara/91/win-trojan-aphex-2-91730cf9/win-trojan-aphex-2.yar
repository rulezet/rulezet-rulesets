rule Win_Trojan_Aphex_2
{
strings:
	$a0 = { 558bec83c4f0b8f4a24600e86c92f9ffe8f3edffffe8068bf9ff8bc000000000 }


condition:
	$a0
}