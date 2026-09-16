rule Win_Spyware_ye_184
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]b57bbf14d0f7a2d4fea3ce38587d35 }


condition:
	$a0
}