rule Win_Trojan_Bancos_1731
{
strings:
	$a0 = { ad3f5ec47b214e390e4ecb7b16222398c2ee1b1f8bc1381368eb03eb41ba6ae0ce836b472e7c5ec340c5fdd82d97a3723cc545ba3bbfd76d8f0bfe31793086803b7fd174acae }


condition:
	$a0
}