rule Win_Trojan_Grace_1
{
strings:
	$a0 = { 0e0533d2e88ffde880fd9d727db440b90200ba2005e87efd33c98b163205b80042e872fd8b }


condition:
	$a0
}