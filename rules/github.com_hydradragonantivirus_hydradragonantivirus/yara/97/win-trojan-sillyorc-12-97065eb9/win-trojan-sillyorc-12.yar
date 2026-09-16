rule Win_Trojan_SillyORC_12
{
strings:
	$a0 = { 2180fa1f7519b92900bfa602e8daffbaa602b409cd21b92900bfa602e8d4ffb90f00bfcf02e8c1ffb80143b901 }


condition:
	$a0
}