rule Win_Trojan__0412_0001_001_1
{
strings:
	$a0 = { 21b000e81c00b440b903008d96cf00cd215a5983c91fb80157cd21b43ecd21e976ff33c933 }


condition:
	$a0
}