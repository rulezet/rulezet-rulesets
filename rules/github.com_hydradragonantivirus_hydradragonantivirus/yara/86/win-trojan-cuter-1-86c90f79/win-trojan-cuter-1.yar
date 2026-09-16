rule Win_Trojan_Cuter_1
{
strings:
	$a0 = { e84f0000007368656c6c33322e646c6c005368 }


condition:
	$a0
}