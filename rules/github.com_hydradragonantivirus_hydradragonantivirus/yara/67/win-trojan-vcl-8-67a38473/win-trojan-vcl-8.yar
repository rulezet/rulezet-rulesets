rule Win_Trojan_Vcl_8
{
strings:
	$a0 = { 2e8aa6????8db6????b9a4032e302446e2fac3 }


condition:
	$a0
}