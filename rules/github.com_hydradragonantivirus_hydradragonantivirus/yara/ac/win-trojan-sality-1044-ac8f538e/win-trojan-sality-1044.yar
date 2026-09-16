rule Win_Trojan_Sality_1044
{
strings:
	$a0 = { 83c7018a440500300780e9015e4e0f85??ffffff }


condition:
	$a0
}