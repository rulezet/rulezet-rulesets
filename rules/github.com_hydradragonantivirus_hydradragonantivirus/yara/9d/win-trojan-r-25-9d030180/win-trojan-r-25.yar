rule Win_Trojan_R_25
{
strings:
	$a0 = { 0f00b440b986018d960401cd21e80100c38b8621018db64701b9a20031044646e2fac3 }


condition:
	$a0
}