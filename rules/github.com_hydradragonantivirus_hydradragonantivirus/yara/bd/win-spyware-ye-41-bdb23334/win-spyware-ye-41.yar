rule Win_Spyware_ye_41
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]26f4308541600bbde7943fa9c9eea6 }


condition:
	$a0
}