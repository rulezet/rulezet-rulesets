rule Win_Trojan_Moonlite_3
{
strings:
	$a0 = { 1600eb26e811008d960301b9ca01b440cd21e80300c3 }


condition:
	$a0
}