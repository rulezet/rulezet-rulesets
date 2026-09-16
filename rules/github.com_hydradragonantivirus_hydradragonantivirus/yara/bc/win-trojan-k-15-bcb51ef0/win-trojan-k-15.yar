rule Win_Trojan_K_15
{
strings:
	$a0 = { 908b1edf04b440cd217303e9a30033c933d28b1edf0433c0b442cd217303e99000bae104b9 }


condition:
	$a0
}