rule Win_Trojan_Telecom_1
{
strings:
	$a0 = { 18bf5500b20cb9740e03fd8a1d80c32e }


condition:
	$a0
}