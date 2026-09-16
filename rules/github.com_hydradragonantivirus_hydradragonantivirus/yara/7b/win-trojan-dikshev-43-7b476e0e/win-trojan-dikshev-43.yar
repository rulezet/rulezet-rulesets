rule Win_Trojan_Dikshev_43
{
strings:
	$a0 = { 8d0233c9b43ccd2193b440ba4f02b93e00cd21b43ecd21ba4b0233c9b43ccd2193b44033d2fec6 }


condition:
	$a0
}