rule Win_Trojan_HOMER_1
{
strings:
	$a0 = { 3c32c9ba6c00cd21721c8bd8b4408b0e6a00ba8700cd21b43ecd21ba6c00b80143b92200cd21ba }


condition:
	$a0
}