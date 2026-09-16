rule Win_Trojan_Pit_1
{
strings:
	$a0 = { 80fce97403b400c383c3038a2780fc127403b400c3 }


condition:
	$a0
}