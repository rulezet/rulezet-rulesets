rule Win_Trojan_VComm_1
{
strings:
	$a0 = { fc037504b402eb0780fc0b7502b40a }


condition:
	$a0
}