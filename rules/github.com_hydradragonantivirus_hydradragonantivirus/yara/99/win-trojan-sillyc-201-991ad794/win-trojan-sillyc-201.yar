rule Win_Trojan_SillyC_201
{
strings:
	$a0 = { 32c0642403cf30ada7c6ffbbe71373940fb5669a3dbf2ccb6ffd170dd9be87e7bddb6a11f2 }


condition:
	$a0
}