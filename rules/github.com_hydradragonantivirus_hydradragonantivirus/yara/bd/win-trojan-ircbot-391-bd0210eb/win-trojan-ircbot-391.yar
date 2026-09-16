rule Win_Trojan_IRCBot_391
{
strings:
	$a0 = { e83bffffff05d1320000ffe0e82fffffff05c72c0000 }


condition:
	$a0
}