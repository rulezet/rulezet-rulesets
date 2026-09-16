rule Win_Trojan_Why_Windows_1
{
strings:
	$a0 = { 83c206cd21b44e8d940301b90600cd213d120074548d940a }


condition:
	$a0
}