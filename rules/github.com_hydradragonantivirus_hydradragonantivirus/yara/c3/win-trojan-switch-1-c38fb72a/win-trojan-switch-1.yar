rule Win_Trojan_Switch_1
{
strings:
	$a0 = { 03d20446483d000077f7e9befc }


condition:
	$a0
}