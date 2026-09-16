rule Win_Spyware_ye_61
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]3a804491557c2f597b2043b5ddfaaa }


condition:
	$a0
}