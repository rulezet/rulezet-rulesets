rule Win_Trojan_Bancos_708
{
strings:
	$a0 = { 7b9cf0d9e22cad5d44cc738828f53b1579c89f7dde182b7c91cee949258dbf21c15e9c1e5cf92a19a7df9dbe7a640592e527e398a24309aaf928bec952d7f2f908 }


condition:
	$a0
}