rule Win_Trojan_JFA_2
{
strings:
	$a0 = { bf0002b910008a25f6d4882547e2f7b42fcd21899cf1048c84ef04ba890403d6b41acd21ba }


condition:
	$a0
}