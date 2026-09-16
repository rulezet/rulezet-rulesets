rule Win_Trojan_Bizarre_1
{
strings:
	$a0 = { bcfab48dc4c92bef040a1bc202ec0e04ecdc04bc0416c92bfac4710c }


condition:
	$a0
}