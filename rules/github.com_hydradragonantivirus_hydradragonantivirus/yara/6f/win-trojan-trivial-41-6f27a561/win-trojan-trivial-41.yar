rule Win_Trojan_Trivial_41
{
strings:
	$a0 = { b90000ba5301cd21720bb96600ba000193b4 }


condition:
	$a0
}