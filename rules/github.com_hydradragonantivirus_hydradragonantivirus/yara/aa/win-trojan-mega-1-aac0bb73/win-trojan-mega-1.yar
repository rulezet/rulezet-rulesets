rule Win_Trojan_Mega_1
{
strings:
	$a0 = { 1fb81335cd21891e057d8c06077db81325baac7ccd21bf0a00b80102bb42010e07b90100ba0000cd13730733c0cd13 }


condition:
	$a0
}