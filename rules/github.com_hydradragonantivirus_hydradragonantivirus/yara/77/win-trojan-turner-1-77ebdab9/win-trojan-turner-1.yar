rule Win_Trojan_Turner_1
{
strings:
	$a0 = { 747c3b8f7038f40008bd8092747cb7f4f90008d68088747c }


condition:
	$a0
}