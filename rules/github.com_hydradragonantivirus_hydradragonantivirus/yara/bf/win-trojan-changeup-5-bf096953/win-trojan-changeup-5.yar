rule Win_Trojan_Changeup_5
{
strings:
	$a0 = { 4d6f64756c653100706c6175646174696f6e }


condition:
	$a0
}