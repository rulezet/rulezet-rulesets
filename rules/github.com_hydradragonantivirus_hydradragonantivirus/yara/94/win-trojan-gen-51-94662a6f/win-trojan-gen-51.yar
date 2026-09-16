rule Win_Trojan_Gen_51
{
strings:
	$a0 = { 5b81c31000b9700633f68030bd46e2fa }


condition:
	$a0
}