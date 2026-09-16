rule Win_Trojan_ViennaDr_1
{
strings:
	$a0 = { 2c00bf00005e5683c61aacb90080f2aeb90400acae75 }


condition:
	$a0
}