rule Win_Trojan_Trivial_570
{
strings:
	$a0 = { e8000050b8023dba????cd21b7??ba0001938acccd21 }


condition:
	$a0
}