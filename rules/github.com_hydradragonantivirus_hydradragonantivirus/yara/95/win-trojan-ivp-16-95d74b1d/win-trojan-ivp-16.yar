rule Win_Trojan_IVP_16
{
strings:
	$a0 = { 1601b9d6022e8a272e32a402042e882743e2f2c3 }


condition:
	$a0
}