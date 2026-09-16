rule Win_Trojan_WereWolf_3
{
strings:
	$a0 = { ff37ff7702c707be01894702c7060600f0ff890e04 }


condition:
	$a0
}