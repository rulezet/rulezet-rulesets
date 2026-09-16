rule Win_Trojan_LittBrother_1
{
strings:
	$a0 = { 01b42550cd21c516390233c9b45bcd217220930e1fb9350190ba0001b440cd213bc19cb43ecd }


condition:
	$a0
}