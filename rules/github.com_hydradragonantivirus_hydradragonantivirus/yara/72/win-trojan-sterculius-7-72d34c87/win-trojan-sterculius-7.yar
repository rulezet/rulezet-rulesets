rule Win_Trojan_Sterculius_7
{
strings:
	$a0 = { 24b440b91101bae001e887ffb8004233c999e87effb440b90400ba36028bf2896c01e86eff595a }


condition:
	$a0
}