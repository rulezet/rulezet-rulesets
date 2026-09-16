rule Win_Trojan_Small_4499
{
strings:
	$a0 = { 8d8062aa7504506862343504e84900000089c7508d15744dff015250e8 }


condition:
	$a0
}