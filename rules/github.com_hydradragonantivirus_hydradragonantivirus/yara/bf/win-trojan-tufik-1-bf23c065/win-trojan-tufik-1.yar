rule Win_Trojan_Tufik_1
{
strings:
	$a0 = { e8000000005b81eb59344000ff3424e8bffeffff0bc07505e95f0c00 }


condition:
	$a0
}