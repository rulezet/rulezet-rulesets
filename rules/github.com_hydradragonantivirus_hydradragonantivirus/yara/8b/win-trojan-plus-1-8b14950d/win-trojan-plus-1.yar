rule Win_Trojan_Plus_1
{
strings:
	$a0 = { bd2301b9e600fa87ec5b5831d85049e2 }


condition:
	$a0
}