rule Win_Trojan_Touch_1
{
strings:
	$a0 = { 64473b056438380ed075d23c11c4e2c76445fe8cce }


condition:
	$a0
}