rule Win_Trojan_PS_MPC_9
{
strings:
	$a0 = { 01b440b9ea01cc33d2b8004233c9cc8d965a03b440 }


condition:
	$a0
}