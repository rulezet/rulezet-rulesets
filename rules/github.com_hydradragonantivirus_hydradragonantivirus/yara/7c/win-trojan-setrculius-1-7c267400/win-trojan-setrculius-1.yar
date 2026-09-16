rule Win_Trojan_Setrculius_1
{
strings:
	$a0 = { 04894c025bb440b9b80190bae001e80effb8004233c933d2e804ff83ff01740eb90400ba6102 }


condition:
	$a0
}