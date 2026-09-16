rule Win_Trojan_Sevilla_1
{
strings:
	$a0 = { 0e1fbb1304be517ca09b7db94b01280446e2fb }


condition:
	$a0
}