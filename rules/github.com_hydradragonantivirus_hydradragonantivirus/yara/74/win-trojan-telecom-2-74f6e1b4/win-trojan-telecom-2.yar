rule Win_Trojan_Telecom_2
{
strings:
	$a0 = { b20083fb007418bf5600b2??b9c80e03fd8a1d80????32d8881d }


condition:
	$a0
}