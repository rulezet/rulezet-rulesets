rule Win_Trojan_Agent_35470
{
strings:
	$a0 = { 436f7272757074204461746121006a00b80070410068 }


condition:
	$a0
}