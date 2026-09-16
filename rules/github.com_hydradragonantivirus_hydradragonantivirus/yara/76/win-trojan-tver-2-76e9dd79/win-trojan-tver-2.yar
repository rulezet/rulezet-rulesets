rule Win_Trojan_Tver_2
{
strings:
	$a0 = { 33d2b000cd21b91800baec010e1fb440cd21b8024233c933d2cd21b91402baea010e1fb440cd }


condition:
	$a0
}