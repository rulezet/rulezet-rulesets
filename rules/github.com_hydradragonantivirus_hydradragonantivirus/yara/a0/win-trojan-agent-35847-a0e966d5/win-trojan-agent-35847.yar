rule Win_Trojan_Agent_35847
{
strings:
	$a0 = { 496e6a65637444756d702e646c6c005465737444756d7048617368 }


condition:
	$a0
}