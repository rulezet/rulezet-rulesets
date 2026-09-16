rule Win_Trojan_Bexelets_1
{
strings:
	$a0 = { 3242305142414b4131696966326f4d58 }


condition:
	$a0
}