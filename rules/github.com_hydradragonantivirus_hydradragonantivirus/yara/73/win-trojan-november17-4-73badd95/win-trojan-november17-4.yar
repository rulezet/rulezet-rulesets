rule Win_Trojan_November17_4
{
strings:
	$a0 = { ba0001b94802b440cd2172182bc1751433d233c9b80042cd217209ba4003b104b440cd215a59 }


condition:
	$a0
}