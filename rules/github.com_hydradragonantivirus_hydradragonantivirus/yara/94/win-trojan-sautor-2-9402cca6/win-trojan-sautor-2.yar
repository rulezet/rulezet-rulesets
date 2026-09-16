rule Win_Trojan_Sautor_2
{
strings:
	$a0 = { 5b6175746f72756e5d0d0a6f70656e3d72657065722e657865 }


condition:
	$a0
}