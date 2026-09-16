rule Win_Trojan_Boot_17
{
strings:
	$a0 = { 32e4cd138ec197408bdd41ba80002e3816b80174345232d250cd13585abb????e8????7226e8????7421b8010350b90400cd132e8816????0e07bebe07bfbe01b94000f3a45833db41cd13 }


condition:
	$a0
}