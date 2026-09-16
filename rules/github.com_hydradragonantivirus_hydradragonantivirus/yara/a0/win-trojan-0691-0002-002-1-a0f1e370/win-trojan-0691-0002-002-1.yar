rule Win_Trojan__0691_0002_002_1
{
strings:
	$a0 = { b90700e8ca03e86900b440b91e00bab207cd215a5233c9b80042cd21be2100bfd007b98d075d81 }


condition:
	$a0
}