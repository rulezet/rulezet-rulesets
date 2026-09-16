rule Win_Trojan_Vanbot_9
{
strings:
	$a0 = { e8f7feffff0517740000ffe0e8ebfeffff052a730000ffe0 }


condition:
	$a0
}