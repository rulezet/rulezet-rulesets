rule Win_Trojan_SillyOC_20
{
strings:
	$a0 = { b80057cd215152b440b92200ba0001cd21b440b99800baba01cd215a59b80157cd215ab801 }


condition:
	$a0
}