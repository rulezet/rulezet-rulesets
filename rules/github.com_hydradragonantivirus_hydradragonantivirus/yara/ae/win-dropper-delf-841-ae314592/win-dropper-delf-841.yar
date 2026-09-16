rule Win_Dropper_Delf_841
{
strings:
	$a0 = { 8d4decba8c3c0010a164560010e816fbffff8b55ecb864560010e8c5f4ffffb864560010e8dbf5ffffe856fcffff33c05a595964891068733c0010 }


condition:
	$a0
}