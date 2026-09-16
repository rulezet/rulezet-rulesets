rule Win_Trojan_Flowers_1
{
strings:
	$a0 = { 45053dfb807403eb0890268b45073dfcfa07c3b8003d }


condition:
	$a0
}