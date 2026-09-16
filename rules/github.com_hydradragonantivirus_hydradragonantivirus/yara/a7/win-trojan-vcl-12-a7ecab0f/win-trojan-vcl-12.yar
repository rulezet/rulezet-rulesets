rule Win_Trojan_VCL_12
{
strings:
	$a0 = { 0601e92b018db61a0189f7bb0301e81501bf00018db62902b90300f3a4b44e33c98d96e101cd217306e9a800e9 }


condition:
	$a0
}