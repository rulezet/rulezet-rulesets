rule Win_Trojan_Torm_1
{
strings:
	$a0 = { 80bcc5004d7435b8024233c933d2cd212d0400a3cf01b440b9cd008bd6cd21721fb8004233c933d2 }


condition:
	$a0
}