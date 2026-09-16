rule Win_Trojan_Justice_1
{
strings:
	$a0 = { 895d102e8c4512b435b013cd212e }


condition:
	$a0
}