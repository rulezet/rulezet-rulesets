rule Win_Trojan_Bancos_730
{
strings:
	$a0 = { 32000f3354c9f8cae4faaaf2380afc6cf73ca0c92749eae01bfa4b1829201b15fcebc14cfd504f257bfc9db601380d31fe44c869b8272cac5ee929cecb56116ac578369a649143de0db68c07 }


condition:
	$a0
}