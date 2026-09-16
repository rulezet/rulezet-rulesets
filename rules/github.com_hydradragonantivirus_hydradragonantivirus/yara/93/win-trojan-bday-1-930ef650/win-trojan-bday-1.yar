rule Win_Trojan_BDay_1
{
strings:
	$a0 = { 0f018a260e01b953028a0432c48804463bf175f5c3 }


condition:
	$a0
}