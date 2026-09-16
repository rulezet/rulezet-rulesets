rule Win_Trojan_Krile_5
{
strings:
	$a0 = { aa29a8cc5f3b2ae50826fa55cc2e5caa55f265b88cd3153375813ee80f009ae8f9ff9a9ceb019a }


condition:
	$a0
}