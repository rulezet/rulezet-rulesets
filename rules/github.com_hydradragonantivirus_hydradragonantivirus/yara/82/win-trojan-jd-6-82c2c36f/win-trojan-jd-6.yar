rule Win_Trojan_JD_6
{
strings:
	$a0 = { 1401b440cd2133c9b8004299cd21b440b104ba1202cd21 }


condition:
	$a0
}