rule Win_Spyware_ye_54
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]33f93d8a4e75204a741944b6defbab }


condition:
	$a0
}