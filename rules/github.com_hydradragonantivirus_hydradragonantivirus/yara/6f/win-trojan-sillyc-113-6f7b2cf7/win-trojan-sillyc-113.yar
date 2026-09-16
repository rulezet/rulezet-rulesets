rule Win_Trojan_SillyC_113
{
strings:
	$a0 = { c13e89860002b4408d962001b9e000cd2133c0e82800b4408d96ff01cd218b1635f959b8 }


condition:
	$a0
}