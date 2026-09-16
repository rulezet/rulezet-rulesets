rule Win_Spyware_ye_36
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]21ef2bf83c5b0eb8da872a9cc4e191 }


condition:
	$a0
}