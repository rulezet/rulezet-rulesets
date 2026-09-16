rule Win_Trojan_Trivial_279
{
strings:
	$a0 = { 0a01cd217307c32a2e434f4d00b8023dba9e00cd21720fb740b92d00ba000193cd21b43ecd21b44f }


condition:
	$a0
}