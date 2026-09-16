rule Win_Trojan_Medbot_98
{
strings:
	$a0 = { ff4904780b8b118802ff010fb6c0eb0c0fbec05150e80700????595983f8ff75030906c3ff06c3 }


condition:
	$a0
}