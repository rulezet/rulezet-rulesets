rule Win_Trojan_VGEN_189
{
strings:
	$a0 = { 04008d8e9002ffd1543cd9d5cd946abfee9052a7ee9072d8eee21bc41bc417957a49eda0c83d213960c062d85318ed }


condition:
	$a0
}