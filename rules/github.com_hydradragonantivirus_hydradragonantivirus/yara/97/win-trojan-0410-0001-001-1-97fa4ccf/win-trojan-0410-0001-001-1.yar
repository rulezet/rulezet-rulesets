rule Win_Trojan__0410_0001_001_1
{
strings:
	$a0 = { cd21b000e81b00b440b903008d96ba00cd215a5983c91fb80157cd21b43ecd21eb8b33c933d2 }


condition:
	$a0
}