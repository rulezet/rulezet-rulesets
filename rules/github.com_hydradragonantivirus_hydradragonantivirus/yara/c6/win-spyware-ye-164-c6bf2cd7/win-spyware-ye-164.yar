rule Win_Spyware_ye_164
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a16fab78bcdb8e385a07aa1c446111 }


condition:
	$a0
}