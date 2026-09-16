rule Win_Spyware_ye_172
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a977b300c4e396c0e28f32a4cce999 }


condition:
	$a0
}