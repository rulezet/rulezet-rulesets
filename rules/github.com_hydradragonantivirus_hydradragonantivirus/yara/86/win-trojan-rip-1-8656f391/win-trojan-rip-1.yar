rule Win_Trojan_RIP_1
{
strings:
	$a0 = { 0200ba070203d7cd21b8004233c92e8b951002cd217253c7850702eb00b440b90100ba0702 }


condition:
	$a0
}