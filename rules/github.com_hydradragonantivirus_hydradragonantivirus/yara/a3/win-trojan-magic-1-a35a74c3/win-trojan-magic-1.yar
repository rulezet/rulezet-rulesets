rule Win_Trojan_Magic_1
{
strings:
	$a0 = { 0100c6060000e9b8004233c9cd21b90300ba0000b440cd21b801575a5983c91fcd21b43ecd21 }


condition:
	$a0
}