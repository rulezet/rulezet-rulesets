rule Win_Trojan_Vienna_Parasite_1
{
strings:
	$a0 = { 80f2aeb90400acae75ede2fa5e07897c41908bfe83 }


condition:
	$a0
}