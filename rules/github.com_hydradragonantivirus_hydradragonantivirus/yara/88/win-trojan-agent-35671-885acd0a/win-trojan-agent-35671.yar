rule Win_Trojan_Agent_35671
{
strings:
	$a0 = { 6683e8c081f7f21f5a3889dec1c11ae8990000006daa380000181c00006a6fb9 }

	$a1 = { 62265c3a07a0decc38b7 }

	$a2 = { 5778533a }


condition:
	$a0 and $a1 and $a2
}