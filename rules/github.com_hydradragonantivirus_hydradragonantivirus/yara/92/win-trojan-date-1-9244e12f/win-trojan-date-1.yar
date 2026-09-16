rule Win_Trojan_Date_1
{
strings:
	$a0 = { 010100550001000100ffff00000000b1030000050000004e03 }


condition:
	$a0
}