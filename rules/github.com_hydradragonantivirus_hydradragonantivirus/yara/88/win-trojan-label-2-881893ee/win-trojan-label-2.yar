rule Win_Trojan_Label_2
{
strings:
	$a0 = { 8c065100cd9ceb4780fc0275f71e5657 }


condition:
	$a0
}