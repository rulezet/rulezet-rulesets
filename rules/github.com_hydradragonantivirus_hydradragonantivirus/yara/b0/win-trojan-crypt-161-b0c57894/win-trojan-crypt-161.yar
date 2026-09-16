rule Win_Trojan_Crypt_161
{
strings:
	$a0 = { 6869d60000e8c6fdffff6869d60000e8bcfdffff83c408e8a4ffffff??c0742f680401000068b02160006a00ff1508106000e829ffffff50 }


condition:
	$a0
}