rule Win_Trojan_AT_9
{
strings:
	$a0 = { c933d2cd21b4408d54ffb103892ccd21b43ecd211f61ea }


condition:
	$a0
}