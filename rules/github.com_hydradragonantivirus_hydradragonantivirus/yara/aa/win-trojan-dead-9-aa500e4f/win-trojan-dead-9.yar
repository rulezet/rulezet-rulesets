rule Win_Trojan_Dead_9
{
strings:
	$a0 = { 9a028d961e05cd21b80242e864002d04003e8986c404b440b935018d96bf03cd21b80042e84800 }


condition:
	$a0
}