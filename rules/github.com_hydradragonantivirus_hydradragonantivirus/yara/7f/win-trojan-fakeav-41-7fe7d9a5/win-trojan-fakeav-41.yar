rule Win_Trojan_Fakeav_41
{
strings:
	$a0 = { 5589e581ec440100006a008d8520ffffff50e8b7dcffff2df60800002d4f050000255c1d00001da41d }


condition:
	$a0
}