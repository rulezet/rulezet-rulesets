rule Win_Trojan_AntiPascal_1
{
strings:
	$a0 = { b440cd2132c0e82e00582d0300a38e00b90300ba8d00b440cd21b002e81800b9470233d2b4 }


condition:
	$a0
}