rule Win_Trojan_Marbas_2
{
strings:
	$a0 = { 17018bfeb9ce04ac3400aae2fae5400d2da125ffbf88862206c3 }


condition:
	$a0
}