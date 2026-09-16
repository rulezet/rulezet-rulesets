rule Win_Trojan_ChristmasViolator_1
{
strings:
	$a0 = { acb90080f2aeb90400acae75ede2fa }


condition:
	$a0
}