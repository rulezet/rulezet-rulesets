rule Win_Trojan_Delf_2264
{
strings:
	$a0 = { 558becb9150000006a006a004975f953b8 }

	$a1 = { 77696d616d703835 }


condition:
	$a0 and $a1
}