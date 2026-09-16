rule Win_Trojan_SillyOE_4
{
strings:
	$a0 = { ffe87701be4005bf3906e82f00b44c32c0cd21b40332ffcd1033c08ac2fec0a3bc048ac6fec0 }


condition:
	$a0
}