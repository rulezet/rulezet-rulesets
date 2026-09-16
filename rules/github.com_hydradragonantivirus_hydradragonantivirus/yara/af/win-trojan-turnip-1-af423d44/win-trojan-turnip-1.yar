rule Win_Trojan_Turnip_1
{
strings:
	$a0 = { 4d69cd2181fa4e547454e8f4000e07b44a33db4bcd21b44a83eb1390cd21b448bb120090cd218ec0488ed8c6 }


condition:
	$a0
}