rule Win_Trojan_Zorm_1
{
strings:
	$a0 = { 1100b43dcd210411bb24002e300743e2fa90 }


condition:
	$a0
}