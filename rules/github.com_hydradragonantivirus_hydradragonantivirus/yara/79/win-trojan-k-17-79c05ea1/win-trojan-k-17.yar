rule Win_Trojan_K_17
{
strings:
	$a0 = { 01a095032ea20101a096032ea20201b90001bb00002e }


condition:
	$a0
}