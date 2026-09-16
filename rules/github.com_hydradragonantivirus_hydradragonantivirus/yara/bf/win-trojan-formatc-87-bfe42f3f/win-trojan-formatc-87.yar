rule Win_Trojan_FormatC_87
{
strings:
	$a0 = { 406563686f206f6666206563686f2079207c20666f726d617420633a }


condition:
	$a0
}