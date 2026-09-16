rule Win_Trojan_Nop_1
{
strings:
	$a0 = { 3602cd21b44eba2e0233c9cd21724db43dba5402b000cd217242a3260293b43fba2402b90200cd21b43e8b1e26 }


condition:
	$a0
}