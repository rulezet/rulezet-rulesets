rule Win_Trojan_VGEN_723
{
strings:
	$a0 = { 1335cd21891eb97d8c06bb7db81325ba487dcd21bf0a00b80102bb41010e07b90100ba8000cd13730733c0cd13 }


condition:
	$a0
}