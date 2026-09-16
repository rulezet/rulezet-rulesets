rule Win_Trojan_Vienna_83
{
strings:
	$a0 = { b90080f2aeb90400acae75eae2fa5e07897c24908bfe }


condition:
	$a0
}