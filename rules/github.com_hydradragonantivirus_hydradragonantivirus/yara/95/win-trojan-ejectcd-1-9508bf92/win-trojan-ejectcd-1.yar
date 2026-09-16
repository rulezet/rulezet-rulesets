rule Win_Trojan_Ejectcd_1
{
strings:
	$a0 = { 636f6c6364726f6d732e636f756e742d31636f6c6364726f6d732e6974656d2869292e656a656374 }


condition:
	$a0
}