rule Win_Trojan_I13_1
{
strings:
	$a0 = { cd21e8d9022d0b038bd0b8004233c9cd2133d2b440cd21e8bf02b440ba1509b90e00cd21b43fba }


condition:
	$a0
}