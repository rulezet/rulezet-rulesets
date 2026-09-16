rule Win_Trojan_Peach_1
{
strings:
	$a0 = { e851ffb440b918008bd7807d015a7406b91300ba4001cd21 }


condition:
	$a0
}