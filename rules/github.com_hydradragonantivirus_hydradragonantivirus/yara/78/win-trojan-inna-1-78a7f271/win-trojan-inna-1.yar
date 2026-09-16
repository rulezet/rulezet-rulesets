rule Win_Trojan_Inna_1
{
strings:
	$a0 = { 9a0000e2005589e5b00950bf212e1e579ae101a700b00950bf0000b8000050579af901a700e8dbf5bf180a0e57e85efe }


condition:
	$a0
}