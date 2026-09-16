rule Win_Trojan_Beer_11
{
strings:
	$a0 = { 9080fc3b7503e918ff3d003d740f3d023d740a80fc5674 }


condition:
	$a0
}