rule Win_Trojan_Constructor_32
{
strings:
	$a0 = { 72006500740072006f00000f77006100680061006e006b0068 }


condition:
	$a0
}