rule Win_Trojan_Leprosy_24
{
strings:
	$a0 = { 0b0251e80f005bb93a02ba0001b440cd21e80100c3bb }


condition:
	$a0
}