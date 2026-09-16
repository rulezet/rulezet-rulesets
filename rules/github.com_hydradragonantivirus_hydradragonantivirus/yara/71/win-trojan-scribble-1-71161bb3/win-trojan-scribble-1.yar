rule Win_Trojan_Scribble_1
{
strings:
	$a0 = { 5e5dc3558beca10c03051e008bd033c9b001b443cd }


condition:
	$a0
}