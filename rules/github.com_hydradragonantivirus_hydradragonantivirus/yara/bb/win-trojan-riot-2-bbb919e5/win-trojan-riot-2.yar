rule Win_Trojan_Riot_2
{
strings:
	$a0 = { e80100c38b8621018db64701b99d0031044646e2fac3 }


condition:
	$a0
}