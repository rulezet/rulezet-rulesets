rule Win_Trojan_Trivial_176
{
strings:
	$a0 = { 2a2e2a00518bd1b44ecd21ba9e00b8023dcd215a47686f7374446f6793b440cd21c3 }


condition:
	$a0
}