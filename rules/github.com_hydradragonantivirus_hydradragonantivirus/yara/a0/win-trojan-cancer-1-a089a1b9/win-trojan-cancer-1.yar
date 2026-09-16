rule Win_Trojan_Cancer_1
{
strings:
	$a0 = { baf401cd217202eba9ba8000b41a }


condition:
	$a0
}