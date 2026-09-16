rule Win_Trojan_ReplayII_2
{
strings:
	$a0 = { 3c4e53750f814402a502b440b90700bae800cd2133c0e81a00b440bae400b90400cd21b43ecd21 }


condition:
	$a0
}