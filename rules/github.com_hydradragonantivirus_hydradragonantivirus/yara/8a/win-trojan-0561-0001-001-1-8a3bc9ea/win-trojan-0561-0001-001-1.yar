rule Win_Trojan__0561_0001_001_1
{
strings:
	$a0 = { b80042e82b008d96fe01b90500b440cd21fe8605025a59b80157cd21b43ecd2180be050201 }


condition:
	$a0
}