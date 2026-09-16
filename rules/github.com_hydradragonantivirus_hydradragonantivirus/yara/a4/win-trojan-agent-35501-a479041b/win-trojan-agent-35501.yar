rule Win_Trojan_Agent_35501
{
strings:
	$a0 = { 73686974646566656e646572[0-20]746370757267 }


condition:
	$a0
}