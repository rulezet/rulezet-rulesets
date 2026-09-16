rule Win_Trojan_Delf_517
{
strings:
	$a0 = { e888fbffff8b55e8b878444000e8e7d7ffffb8443f4000e801feffff8bf0a174444000ba543f4000e89cd9ffff }


condition:
	$a0
}