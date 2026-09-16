rule Win_Trojan_Agent_35859
{
strings:
	$a0 = { 522bd253575056510f84ddfeffffb6df4ea0fe56a79d2b9f9c884dd080b76f9c }


condition:
	$a0
}