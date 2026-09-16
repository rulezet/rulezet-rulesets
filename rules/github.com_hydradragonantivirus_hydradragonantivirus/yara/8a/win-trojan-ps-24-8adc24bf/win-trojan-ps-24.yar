rule Win_Trojan_PS_24
{
strings:
	$a0 = { bb02b2e98896ba02b4408d960301b94a01ccb8004233c933d2ccb903008d96ba02b440ccfe86 }


condition:
	$a0
}