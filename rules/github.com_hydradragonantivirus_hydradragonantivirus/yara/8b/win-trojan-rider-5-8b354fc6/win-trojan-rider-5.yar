rule Win_Trojan_Rider_5
{
strings:
	$a0 = { 011e57b87f00509a71098f00a0aa003a46ff75cb89ec5dc3020d0a4a0d0a20c9cdcdcdcdcdcd }


condition:
	$a0
}