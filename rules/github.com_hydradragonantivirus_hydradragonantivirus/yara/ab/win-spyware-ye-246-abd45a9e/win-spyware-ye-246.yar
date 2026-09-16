rule Win_Spyware_ye_246
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]f339fdca0eb5e08a345904f69e3b6b }


condition:
	$a0
}