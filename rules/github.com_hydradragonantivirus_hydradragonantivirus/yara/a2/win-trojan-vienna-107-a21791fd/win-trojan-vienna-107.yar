rule Win_Trojan_Vienna_107
{
strings:
	$a0 = { b90080f2aeb90400acae75ede2fa5e0789bcf9008bfe81 }


condition:
	$a0
}