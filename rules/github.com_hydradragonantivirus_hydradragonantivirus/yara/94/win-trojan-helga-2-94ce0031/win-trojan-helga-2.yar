rule Win_Trojan_Helga_2
{
strings:
	$a0 = { 9052528a573b9032d088573b9043e2f3c360b42ccd2133ca32e9886d10e8 }


condition:
	$a0
}