rule Win_Trojan_ChristmasTree_1
{
strings:
	$a0 = { bf00008bf2acb90080f2aeb90400acae }


condition:
	$a0
}