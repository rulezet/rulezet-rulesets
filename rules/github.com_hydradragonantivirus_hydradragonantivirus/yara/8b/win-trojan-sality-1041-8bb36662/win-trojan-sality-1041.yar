rule Win_Trojan_Sality_1041
{
strings:
	$a0 = { 02c5[0-1]5f83c7018a4405003007fec95e4e0f85??ffffff }


condition:
	$a0
}