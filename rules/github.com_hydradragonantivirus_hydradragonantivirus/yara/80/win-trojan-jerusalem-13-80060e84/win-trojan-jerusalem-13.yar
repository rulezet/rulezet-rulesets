rule Win_Trojan_Jerusalem_13
{
strings:
	$a0 = { 33c0f2af8bd783c202b8004b061f0e }


condition:
	$a0
}