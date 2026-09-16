rule Win_Trojan_Peed_217
{
strings:
	$a0 = { 558bec83ec44535657c745d8??1240008b75d86a06598d7de4f3a5a10c2040000fb6003d }


condition:
	$a0
}