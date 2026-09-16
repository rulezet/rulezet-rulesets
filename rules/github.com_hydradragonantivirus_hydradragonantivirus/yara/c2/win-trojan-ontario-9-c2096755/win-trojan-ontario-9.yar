rule Win_Trojan_Ontario_9
{
strings:
	$a0 = { bf????b9e53782c5d0b0??2e0005d2c847e2f8 }


condition:
	$a0
}