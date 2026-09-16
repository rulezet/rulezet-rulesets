rule Win_Trojan_BHO_102
{
strings:
	$a0 = { 5f7075726563616c6c[0-153]62686f6e65772e444c4c }

	$a1 = { 7b0d0a094e696d6f203d207320274142532054 }


condition:
	$a0 and $a1
}