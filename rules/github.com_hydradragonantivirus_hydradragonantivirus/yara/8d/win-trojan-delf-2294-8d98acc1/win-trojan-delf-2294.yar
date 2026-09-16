rule Win_Trojan_Delf_2294
{
strings:
	$a0 = { 52454d4f5445434f4e54524f4c }

	$a1 = { 4436374238304141344238304137343846383234 }


condition:
	$a0 and $a1
}