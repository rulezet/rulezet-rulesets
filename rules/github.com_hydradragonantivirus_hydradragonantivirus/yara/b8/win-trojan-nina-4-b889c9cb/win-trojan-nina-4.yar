rule Win_Trojan_Nina_4
{
strings:
	$a0 = { 012e8c069601061f8bd3b89125cd21 }


condition:
	$a0
}