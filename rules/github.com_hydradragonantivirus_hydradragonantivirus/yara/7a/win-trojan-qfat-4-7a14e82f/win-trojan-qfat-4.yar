rule Win_Trojan_QFat_4
{
strings:
	$a0 = { 07b500b100b619b250cd10b402b700ba0000cd1007b80200b9b80bfa99cd26fbb8004ccd21 }


condition:
	$a0
}