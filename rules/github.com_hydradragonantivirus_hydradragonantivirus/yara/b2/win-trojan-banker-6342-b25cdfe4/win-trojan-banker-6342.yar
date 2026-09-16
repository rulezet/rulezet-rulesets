rule Win_Trojan_Banker_6342
{
strings:
	$a0 = { 60e803000000e9eb045d4555c3e801000000eb5dbbedffffff03dd81eb00b044 }


condition:
	$a0
}