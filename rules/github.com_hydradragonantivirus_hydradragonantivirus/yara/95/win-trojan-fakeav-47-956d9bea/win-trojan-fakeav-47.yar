rule Win_Trojan_Fakeav_47
{
strings:
	$a0 = { 558bec83c4e0535633c08945e88945e08945e48945ecb8a09d4f00e8a0c3f0ff }


condition:
	$a0
}