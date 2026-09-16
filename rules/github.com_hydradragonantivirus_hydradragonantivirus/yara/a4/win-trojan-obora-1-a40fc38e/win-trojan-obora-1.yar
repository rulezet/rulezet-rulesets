rule Win_Trojan_Obora_1
{
strings:
	$a0 = { b440b91606ba00008b1ec201e8fefce8eefd2e8b0ece0180c91f2e8b16d001b80157e8e8fc }


condition:
	$a0
}