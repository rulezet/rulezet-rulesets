rule Win_Trojan_Barrotes_4
{
strings:
	$a0 = { 83c707b9f9042e802d9347e2f9e9dafe }


condition:
	$a0
}