rule Win_Spyware_ye_45
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]2af03481456c1f496b10b3254d6a1a }


condition:
	$a0
}