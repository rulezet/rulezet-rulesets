rule Win_Trojan_Riot_15
{
strings:
	$a0 = { 0f00b440b97a018d960401cd21e80100c38b8621018db64701b99c0031044646e2fac3 }


condition:
	$a0
}