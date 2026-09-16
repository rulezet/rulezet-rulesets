rule Win_Trojan_Next_1
{
strings:
	$a0 = { b0fd90b451eb00fc909035fa519040902e31019043eb004975eb }


condition:
	$a0
}