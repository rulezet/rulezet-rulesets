rule Win_Trojan_Yanush_2
{
strings:
	$a0 = { 8db66a028bfeacfec0aae85b00b440b9e601908d960a01cd21e84c00b8004233c933d2cd218b }


condition:
	$a0
}