rule Win_Trojan_Crypt_3
{
strings:
	$a0 = { a6005589e531c09a7c02a600e857fbbf7b080e57bf7a021e57b86400509aad07a600c7067a000500e845ff803e }


condition:
	$a0
}