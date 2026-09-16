rule Win_Trojan_Fingers_1
{
strings:
	$a0 = { 3e3000007410501e2ea131002e8e1e3300a30100 }


condition:
	$a0
}