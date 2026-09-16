rule Win_Trojan_Agent_34146
{
strings:
	$a0 = { 60e801000000c2585083c40461eb5ccc }


condition:
	$a0
}