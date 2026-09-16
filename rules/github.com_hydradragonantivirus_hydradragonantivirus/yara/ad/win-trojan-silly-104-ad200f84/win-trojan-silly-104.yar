rule Win_Trojan_Silly_104
{
strings:
	$a0 = { 5c72756e5d3e3e633a5c616c6c7468656261742e726567 }

	$a1 = { 636f707920253020613a5c726561646d652e74 }


condition:
	$a0 and $a1
}