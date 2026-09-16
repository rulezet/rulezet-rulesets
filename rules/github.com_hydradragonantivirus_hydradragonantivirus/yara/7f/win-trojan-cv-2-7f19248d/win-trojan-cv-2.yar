rule Win_Trojan_CV_2
{
strings:
	$a0 = { 9a00005b029a0d00f9019ac4014f015589e50ee82ffe0ee863fa9a48115b0231c0a31615b85000509ab3105b02a3061d }


condition:
	$a0
}