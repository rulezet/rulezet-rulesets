rule Win_Trojan_Rescue_1
{
strings:
	$a0 = { be0000468b075083c30281fb000175f31e068cc88ed88ec0b419cd21a2610cb444b00db7008a1e610c43b508b1 }


condition:
	$a0
}