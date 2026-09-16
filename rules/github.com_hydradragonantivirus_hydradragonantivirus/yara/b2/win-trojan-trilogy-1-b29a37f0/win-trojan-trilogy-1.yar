rule Win_Trojan_Trilogy_1
{
strings:
	$a0 = { 9c55568ccd83c50a8db6f6ff56be2601 }


condition:
	$a0
}