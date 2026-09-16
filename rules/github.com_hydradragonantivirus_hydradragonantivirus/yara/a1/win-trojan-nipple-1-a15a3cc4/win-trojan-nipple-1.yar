rule Win_Trojan_Nipple_1
{
strings:
	$a0 = { e98944feb440b1d0ba0001cd2126c745150000b440b1038d54fdcd21b80157 }


condition:
	$a0
}