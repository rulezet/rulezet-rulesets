rule Win_Trojan_LX_1
{
strings:
	$a0 = { baac05b9a200cd21b802429933c9cd21e82000b440ba0001b94e05cd21b43ecd21b80143ba50 }


condition:
	$a0
}