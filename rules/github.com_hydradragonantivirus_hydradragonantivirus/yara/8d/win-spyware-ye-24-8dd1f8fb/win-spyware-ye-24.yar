rule Win_Spyware_ye_24
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]15db1ff4305702b4de832e98385d15 }


condition:
	$a0
}