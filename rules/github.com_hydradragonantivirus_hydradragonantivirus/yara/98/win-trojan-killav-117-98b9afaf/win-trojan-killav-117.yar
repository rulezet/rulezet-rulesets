rule Win_Trojan_Killav_117
{
strings:
	$a0 = { 8d85d8fdffff508d85fcfeffff50e8450000008d85d8fdffff5057e89b00000085c07517ffb5e0feffff6a006a01e8700000006a0050e87a000000 }


condition:
	$a0
}