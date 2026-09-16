rule Win_Trojan_Choinka_1
{
strings:
	$a0 = { b90080f2aeb90400acae75eee2fa }


condition:
	$a0
}