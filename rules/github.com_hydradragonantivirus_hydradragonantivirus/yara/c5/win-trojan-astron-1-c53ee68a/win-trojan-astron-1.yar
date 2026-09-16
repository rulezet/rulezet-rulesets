rule Win_Trojan_Astron_1
{
strings:
	$a0 = { 2004b440cd21b43ecd21588ed85ab80143b90100cd }


condition:
	$a0
}