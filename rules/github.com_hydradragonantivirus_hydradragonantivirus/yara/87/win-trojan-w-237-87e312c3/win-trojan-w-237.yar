rule Win_Trojan_W_237
{
strings:
	$a0 = { 9c60e8000000005868071040005b2bc3505d8dbd2910400068 }


condition:
	$a0
}