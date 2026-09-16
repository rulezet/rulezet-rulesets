rule Win_Trojan_Peed_261
{
strings:
	$a0 = { 558bec81ec2c0200005356574a85ce8d3e3bc033de2bc18d394f8d060fb6ce4e }


condition:
	$a0
}