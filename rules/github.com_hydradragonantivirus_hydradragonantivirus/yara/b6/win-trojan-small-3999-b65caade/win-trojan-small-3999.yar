rule Win_Trojan_Small_3999
{
strings:
	$a0 = { bfcbfcb6f881c73565890789fe8d9fd01afe0481eb5416fe0453ff15f86640000500e023bf290731 }


condition:
	$a0
}