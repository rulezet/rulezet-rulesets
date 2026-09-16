rule Win_Trojan_Kela_1
{
strings:
	$a0 = { b106d3e02ea344008ec00580002ea3420033dbb806022e803e3e0000740ab90800ba8000cd }


condition:
	$a0
}