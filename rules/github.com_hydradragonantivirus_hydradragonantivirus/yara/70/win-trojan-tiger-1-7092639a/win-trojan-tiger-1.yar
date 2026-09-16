rule Win_Trojan_Tiger_1
{
strings:
	$a0 = { 0102bb6e0703ddcd13be6e0703f583c603c7045454ba8001b90100b80103bb6e0703ddcd13 }


condition:
	$a0
}