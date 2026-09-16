rule Win_Spyware_ye_72
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]458b4fa46007b2e48e335e48680d45 }


condition:
	$a0
}