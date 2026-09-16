rule Win_Trojan_Delf_1434
{
strings:
	$a0 = { 8d4de4ba4c924800b860924800e859fafcff8b45e48b55f4e89649f8ff85c0740d33c05a5959648910e988030000 }


condition:
	$a0
}