rule Win_Trojan_TPVO_3
{
strings:
	$a0 = { d71b2ad3483b67d02fbd677498090542e57aecdf4b9f6ff7a6c203cf9f337aece5e2d2bc0c64bbbb }


condition:
	$a0
}