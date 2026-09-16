rule Win_Spyware_ye_169
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]a674b005c1e08b3d6714bf29496e26 }


condition:
	$a0
}