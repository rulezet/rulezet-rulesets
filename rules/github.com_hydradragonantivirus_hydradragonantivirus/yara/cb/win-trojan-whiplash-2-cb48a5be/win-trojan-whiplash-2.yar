rule Win_Trojan_Whiplash_2
{
strings:
	$a0 = { b403b906000e1f8bd7b440cd21b80242e8a3032df0118bd0b90000b80042cd21b440b90000cd21 }


condition:
	$a0
}