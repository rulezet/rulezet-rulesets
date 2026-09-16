rule Win_Trojan_Spyremoav_1
{
strings:
	$a0 = { 3c3c7c203c7c495046616b657c3e }


condition:
	$a0
}