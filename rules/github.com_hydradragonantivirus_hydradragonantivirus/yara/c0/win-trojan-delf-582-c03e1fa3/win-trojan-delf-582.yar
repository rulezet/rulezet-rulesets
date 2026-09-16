rule Win_Trojan_Delf_582
{
strings:
	$a0 = { e92666feffebf05b595dc3ffffffff090000004461526b4d6f4f6e2d000000ffffffff010000002d }


condition:
	$a0
}