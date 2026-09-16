rule Win_Trojan_Jerusalem_10
{
strings:
	$a0 = { ff0e1f00eb122ec7061f }


condition:
	$a0
}