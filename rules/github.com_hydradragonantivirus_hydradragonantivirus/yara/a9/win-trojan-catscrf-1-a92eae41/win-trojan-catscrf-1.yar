rule Win_Trojan_Catscrf_1
{
strings:
	$a0 = { cd213defab74d7bb2e02b104d3eb83c303061e0e1f }


condition:
	$a0
}