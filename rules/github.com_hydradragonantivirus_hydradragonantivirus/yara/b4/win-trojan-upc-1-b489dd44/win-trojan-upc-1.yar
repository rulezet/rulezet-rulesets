rule Win_Trojan_UPC_1
{
strings:
	$a0 = { 1000b440b98004ba030103d6cd21e80100c3538b94080189f381c34501b93e04311743e2fb5bc3 }


condition:
	$a0
}