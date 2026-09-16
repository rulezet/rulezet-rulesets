rule Win_Trojan_Cookie_4
{
strings:
	$a0 = { 6e5c72756e5d[0-32]5c636f6f6b6965735c5c7461736b6d67722e6578655c2222 }


condition:
	$a0
}