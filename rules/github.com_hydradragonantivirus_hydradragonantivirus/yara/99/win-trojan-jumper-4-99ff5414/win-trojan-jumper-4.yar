rule Win_Trojan_Jumper_4
{
strings:
	$a0 = { 40eb02ebfa66becd21eb02ebfa66beb44feb02ebfaeb8e66be90c3eb02ebfa2a2e636f6d005b54 }


condition:
	$a0
}