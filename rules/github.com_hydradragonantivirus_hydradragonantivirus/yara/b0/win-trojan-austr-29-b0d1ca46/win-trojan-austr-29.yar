rule Win_Trojan_Austr_29
{
strings:
	$a0 = { cd21b801575a59cd21b43ecd212e803e070103751cb419cd21b93300ba0000cd26 }


condition:
	$a0
}