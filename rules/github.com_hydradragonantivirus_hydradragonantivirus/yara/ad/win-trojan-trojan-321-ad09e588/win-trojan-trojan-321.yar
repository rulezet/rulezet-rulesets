rule Win_Trojan_Trojan_321
{
strings:
	$a0 = { acb90080f2aeb90400acae75ede2fa5e0789bccb008bfe81 }


condition:
	$a0
}