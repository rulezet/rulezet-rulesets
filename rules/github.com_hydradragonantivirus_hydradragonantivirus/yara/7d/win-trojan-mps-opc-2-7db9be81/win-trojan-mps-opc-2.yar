rule Win_Trojan_MPS_OPC_2
{
strings:
	$a0 = { 41b42ccd213ada73042ad3ebf88adaba800203d6b9 }


condition:
	$a0
}