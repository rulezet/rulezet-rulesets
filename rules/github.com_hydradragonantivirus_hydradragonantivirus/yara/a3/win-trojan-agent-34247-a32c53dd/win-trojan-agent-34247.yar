rule Win_Trojan_Agent_34247
{
strings:
	$a0 = { 659b659b659b60e8000000005861e9 }


condition:
	$a0
}