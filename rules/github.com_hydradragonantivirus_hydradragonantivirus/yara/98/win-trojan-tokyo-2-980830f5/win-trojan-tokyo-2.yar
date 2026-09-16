rule Win_Trojan_Tokyo_2
{
strings:
	$a0 = { 2fcd218c060600891e04000e078d1608001e061f07b41a }


condition:
	$a0
}