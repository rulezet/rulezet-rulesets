rule Win_Trojan_Violator_7
{
strings:
	$a0 = { c3cd26c3b42ac606d0030190e8d6ff }


condition:
	$a0
}