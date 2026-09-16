rule Win_Trojan_Fakeav_25
{
strings:
	$a0 = { 68dc000000ff1570324100c1ca1213c86814934000688c00000068 }

	$a1 = { b8b95d2d73687a }


condition:
	$a0 and $a1
}