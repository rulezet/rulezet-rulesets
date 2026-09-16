rule Win_Trojan_Tic_1
{
strings:
	$a0 = { 01568cc880c4108ec0b96d002bfff3a4b41aba00fecd21b44eba6701eb06b43ecd21b44f0e1fcd21b91efe7228b8 }


condition:
	$a0
}