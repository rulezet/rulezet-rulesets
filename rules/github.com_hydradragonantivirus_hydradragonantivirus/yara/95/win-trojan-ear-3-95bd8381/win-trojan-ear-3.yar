rule Win_Trojan_Ear_3
{
strings:
	$a0 = { b918008d96a701cd217232b442b00233c933d2cd217226b440b97c018d960000cd217219b457 }


condition:
	$a0
}