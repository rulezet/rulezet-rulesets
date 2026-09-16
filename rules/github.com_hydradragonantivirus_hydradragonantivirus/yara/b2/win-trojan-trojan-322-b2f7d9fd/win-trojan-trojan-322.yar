rule Win_Trojan_Trojan_322
{
strings:
	$a0 = { acb90080f2aeb90400acae75ede2fa5e07897c42908bfe83 }


condition:
	$a0
}