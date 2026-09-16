rule Win_Spyware_ye_100
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]61af6bb87c1b4e781a476a5c04a1d1 }


condition:
	$a0
}