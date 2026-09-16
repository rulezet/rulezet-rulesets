rule Win_Trojan_Peed_218
{
strings:
	$a0 = { 558bec83ec44535657c745d8??1140008b75d86a06598d7de4f3a5a10c2040000fb6003d8b000000740733c0e9 }


condition:
	$a0
}