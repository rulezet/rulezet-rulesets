rule Win_Trojan_Jumper_5
{
strings:
	$a0 = { b440eb02ebfa66becd21eb02ebfa66beb44feb02ebfaeb8c66be90c3eb02ebfa2a2e636f6d00 }


condition:
	$a0
}