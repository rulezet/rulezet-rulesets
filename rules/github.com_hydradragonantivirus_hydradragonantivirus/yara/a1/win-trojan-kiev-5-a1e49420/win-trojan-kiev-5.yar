rule Win_Trojan_Kiev_5
{
strings:
	$a0 = { 8b87cc01a300018a87ce01a20201b430 }


condition:
	$a0
}