rule Win_Trojan_TVED_2
{
strings:
	$a0 = { c32a92c24303ccc19c491a78ccc1c11476820fe376fc0fe3768d0fe3b10f0fe2e8ec818d8fc2e2a0 }


condition:
	$a0
}