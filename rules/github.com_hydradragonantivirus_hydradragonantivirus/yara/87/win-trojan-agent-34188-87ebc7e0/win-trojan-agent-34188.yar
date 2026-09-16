rule Win_Trojan_Agent_34188
{
strings:
	$a0 = { 558bec74147512e8e90f84ff }


condition:
	$a0
}