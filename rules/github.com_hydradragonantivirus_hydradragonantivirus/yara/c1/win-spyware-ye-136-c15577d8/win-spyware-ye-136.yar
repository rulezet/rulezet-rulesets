rule Win_Spyware_ye_136
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]854b8f64a0c7f2a4cef39e08a8cd85 }


condition:
	$a0
}