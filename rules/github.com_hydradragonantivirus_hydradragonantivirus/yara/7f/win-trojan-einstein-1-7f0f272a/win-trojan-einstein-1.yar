rule Win_Trojan_Einstein_1
{
strings:
	$a0 = { 42cd217231b96e0333d2b440cd2172193bc17515b80042 }


condition:
	$a0
}