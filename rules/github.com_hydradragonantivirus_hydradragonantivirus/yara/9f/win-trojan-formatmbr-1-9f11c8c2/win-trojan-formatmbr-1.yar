rule Win_Trojan_FormatMBR_1
{
strings:
	$a0 = { b8ff05b90100ba8000cd13b8004ccd21 }


condition:
	$a0
}