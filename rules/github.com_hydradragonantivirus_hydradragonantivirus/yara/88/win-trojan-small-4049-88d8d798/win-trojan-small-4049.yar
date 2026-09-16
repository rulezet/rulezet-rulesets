rule Win_Trojan_Small_4049
{
strings:
	$a0 = { 555729ed81c500????fff7dd5589ef81c78f07850581ef3800850583c7056affe82b0000008d88dd1111dd194d008dad }


condition:
	$a0
}