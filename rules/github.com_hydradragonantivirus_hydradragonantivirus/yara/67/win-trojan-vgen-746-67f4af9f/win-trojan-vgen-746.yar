rule Win_Trojan_VGEN_746
{
strings:
	$a0 = { 4f02b9040090bb0100b440cd21b409ba5302cd21be8000bf3203fcac0ac07512b409bada02cd21cd20b409baf902cd }


condition:
	$a0
}