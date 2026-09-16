rule Win_Trojan_Ultimation_1
{
strings:
	$a0 = { 54303d2e63750eeb6050b43e8b5efecd2158e90801b43fb918008d95e300cd2172e781bde3004d }


condition:
	$a0
}