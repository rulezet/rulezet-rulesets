rule Win_Trojan_Delf_2279
{
strings:
	$a0 = { 558becb9120000006a006a004975f95153b8f0e344 }

	$a1 = { 5c7065726674656d702e646c6c }


condition:
	$a0 and $a1
}