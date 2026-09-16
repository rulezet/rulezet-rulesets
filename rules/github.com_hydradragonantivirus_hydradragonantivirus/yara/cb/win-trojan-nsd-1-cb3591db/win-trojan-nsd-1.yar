rule Win_Trojan_NSD_1
{
strings:
	$a0 = { 81c7b9002e8b052ea300012e8b45022ea3020160ba5000b41acd21575a83c20433c9b44ecd21803e6b00fd7308ba6e }


condition:
	$a0
}