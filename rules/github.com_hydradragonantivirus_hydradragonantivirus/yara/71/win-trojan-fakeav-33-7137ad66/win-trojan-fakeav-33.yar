rule Win_Trojan_Fakeav_33
{
strings:
	$a0 = { 558bece863000000e82f000000c9c333c08b4c240cff81ac000000751e600fb6 }


condition:
	$a0
}