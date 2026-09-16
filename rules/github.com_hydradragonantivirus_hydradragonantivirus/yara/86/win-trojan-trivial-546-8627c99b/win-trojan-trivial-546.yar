rule Win_Trojan_Trivial_546
{
strings:
	$a0 = { 33c9b44ecd21[0-5]b8a23dcd21[0-2]ba0001b935008bd8b440cd21b43ecd21 }


condition:
	$a0
}