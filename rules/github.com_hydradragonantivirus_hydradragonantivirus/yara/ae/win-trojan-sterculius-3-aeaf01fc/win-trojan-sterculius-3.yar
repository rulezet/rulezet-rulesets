rule Win_Trojan_Sterculius_3
{
strings:
	$a0 = { b99c0190bae001e87effb8004233c999e875ffb440b9 }


condition:
	$a0
}