rule Win_Trojan_Agent_34220
{
strings:
	$a0 = { 87f987ef87ef87f983ec0468398a476960606161 }


condition:
	$a0
}