rule Win_Trojan_MMIR_1
{
strings:
	$a0 = { b91701ba4002b440cd21b8004233c999cd21b4408bd759cd215a59b80157cd21b43ecd2107 }


condition:
	$a0
}