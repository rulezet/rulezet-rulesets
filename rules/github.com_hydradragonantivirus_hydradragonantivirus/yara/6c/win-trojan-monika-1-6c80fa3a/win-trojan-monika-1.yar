rule Win_Trojan_Monika_1
{
strings:
	$a0 = { 0e1f73463d070275469d890e7b032bc9c70677030100890e790349a09201bb7703cd2672119d }


condition:
	$a0
}