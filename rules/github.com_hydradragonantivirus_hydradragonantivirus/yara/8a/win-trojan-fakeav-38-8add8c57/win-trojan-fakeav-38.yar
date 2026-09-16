rule Win_Trojan_Fakeav_38
{
strings:
	$a0 = { 83ec30e865000000648b00d1e8e8370000005983c404585aff82b00000007514 }


condition:
	$a0
}