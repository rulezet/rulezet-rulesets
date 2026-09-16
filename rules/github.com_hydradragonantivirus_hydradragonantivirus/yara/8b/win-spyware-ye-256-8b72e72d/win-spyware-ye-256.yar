rule Win_Spyware_ye_256
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]fdc307dc18bfea9cc6eb9600a0c5fd }


condition:
	$a0
}