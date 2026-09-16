rule Win_Trojan_Riot_30
{
strings:
	$a0 = { b9e403cd21b8004233c9cd21b440b90400badc03cd21b801572e8b0ed4032e8b16d20380e1e0 }


condition:
	$a0
}