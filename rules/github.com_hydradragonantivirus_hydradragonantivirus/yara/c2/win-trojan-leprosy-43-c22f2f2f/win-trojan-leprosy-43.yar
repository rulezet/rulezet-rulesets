rule Win_Trojan_Leprosy_43
{
strings:
	$a0 = { e9ed008b1ef00153e80f005bb92b02ba0001b440cd }


condition:
	$a0
}