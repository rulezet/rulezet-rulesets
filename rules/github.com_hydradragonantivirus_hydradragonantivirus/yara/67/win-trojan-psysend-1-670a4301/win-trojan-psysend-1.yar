rule Win_Trojan_PsySend_1
{
strings:
	$a0 = { 01e89800b4dccd210ac07445b801f0cd21a29701b804efcd2132c0b9080026382c74064083c6 }


condition:
	$a0
}