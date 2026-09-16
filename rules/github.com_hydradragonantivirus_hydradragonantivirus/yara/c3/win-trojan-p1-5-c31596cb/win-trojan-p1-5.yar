rule Win_Trojan_P1_5
{
strings:
	$a0 = { 40035133472243434979f85a31452247 }


condition:
	$a0
}