rule Win_Trojan_Jungle_1
{
strings:
	$a0 = { b604012e8a860301b99c032e300446e2fac38cd08ed88b }


condition:
	$a0
}