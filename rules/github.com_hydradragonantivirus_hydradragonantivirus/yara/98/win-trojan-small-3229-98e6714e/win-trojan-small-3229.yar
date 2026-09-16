rule Win_Trojan_Small_3229
{
strings:
	$a0 = { 6890e1ffc78fd9ffcfc0d2db6707c89bf583b944f15bb93f5bb322278c0b222f8c1fe62dceb2ffdbd107ff1fd2073f456894d9ffdf71952bd20794f04b18d5dbecc7a45f040995dbf21419eba70720f00b18 }


condition:
	$a0
}