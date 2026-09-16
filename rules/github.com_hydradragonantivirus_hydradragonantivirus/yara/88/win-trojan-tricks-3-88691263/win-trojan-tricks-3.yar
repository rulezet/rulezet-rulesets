rule Win_Trojan_Tricks_3
{
strings:
	$a0 = { 816e0003018b760083c402e88300551e1bab551e19ab1ee4273e01ab9963678bd8f012a8971034aa678b21721e95 }


condition:
	$a0
}