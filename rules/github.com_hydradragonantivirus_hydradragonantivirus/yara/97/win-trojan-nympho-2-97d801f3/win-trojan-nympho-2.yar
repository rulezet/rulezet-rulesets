rule Win_Trojan_Nympho_2
{
strings:
	$a0 = { 40b9e600bae001cd2126896d1526896d17b440b90300baca02cd21b80157268b4d0d }


condition:
	$a0
}