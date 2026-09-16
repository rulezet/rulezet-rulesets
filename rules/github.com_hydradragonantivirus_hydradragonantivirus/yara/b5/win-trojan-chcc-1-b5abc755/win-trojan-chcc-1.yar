rule Win_Trojan_Chcc_1
{
strings:
	$a0 = { 02e8d204e8bc01c3bfef01b02a8805b000884501 }


condition:
	$a0
}