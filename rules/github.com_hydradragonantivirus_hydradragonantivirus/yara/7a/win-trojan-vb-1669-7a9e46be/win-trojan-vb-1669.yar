rule Win_Trojan_VB_1669
{
strings:
	$a0 = { 6f4d736c6f76656e6c79006e670d0a202020afec88885cd9f44e961e6dd41aadeae5d3dcca6a }


condition:
	$a0
}