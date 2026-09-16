rule Win_Trojan_KL_1
{
strings:
	$a0 = { 584850bc007c16b106d3e08ec05087064e00a32601b8e3002e87064c00a32401b90002be }


condition:
	$a0
}