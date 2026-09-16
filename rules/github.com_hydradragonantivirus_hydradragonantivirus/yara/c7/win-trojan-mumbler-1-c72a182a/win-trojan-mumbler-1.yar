rule Win_Trojan_Mumbler_1
{
strings:
	$a0 = { 73740583ee03ebd9ac3c2074fb4ead0d20203d667174684e4e87fbe86d00b440998bcecd21 }


condition:
	$a0
}