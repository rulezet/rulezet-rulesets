rule Win_Trojan_Ray_1
{
strings:
	$a0 = { 01bf7801b928008034f5a4e0fac3b43c8edaba4801cd218bd8c3b440ba7801b92800cd21b43e }


condition:
	$a0
}