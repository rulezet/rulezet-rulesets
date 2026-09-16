rule Win_Trojan_Windthing_1
{
strings:
	$a0 = { 9e1001b910022e8ab638038a2732e6882743e2f75bc3 }


condition:
	$a0
}