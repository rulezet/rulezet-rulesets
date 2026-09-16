rule Win_Trojan__1290_0002_002_1
{
strings:
	$a0 = { b93e00bac909eb06b91d00ba070ab440cd21b8004233c999cd21b440b95a00ba4608cd21c3a1 }


condition:
	$a0
}