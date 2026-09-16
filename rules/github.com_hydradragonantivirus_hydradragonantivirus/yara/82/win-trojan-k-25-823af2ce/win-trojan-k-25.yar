rule Win_Trojan_K_25
{
strings:
	$a0 = { 01a0a5032ea20101a0a6032ea20201b90001bb00002e }


condition:
	$a0
}