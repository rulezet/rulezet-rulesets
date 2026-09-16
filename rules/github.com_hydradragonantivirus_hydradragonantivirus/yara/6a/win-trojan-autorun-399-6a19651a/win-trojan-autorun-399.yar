rule Win_Trojan_Autorun_399
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d74656d703030325c6b65792e657865 }


condition:
	$a0
}