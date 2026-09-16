rule Win_Trojan_Turbo_2
{
strings:
	$a0 = { 0242b900008bd1e81f00ba0001b9c001b440e81400 }


condition:
	$a0
}