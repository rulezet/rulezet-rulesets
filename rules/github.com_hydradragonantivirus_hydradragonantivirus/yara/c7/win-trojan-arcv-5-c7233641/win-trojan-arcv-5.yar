rule Win_Trojan_ARCV_5
{
strings:
	$a0 = { 5f81ef0701e80200eb128db52301b9b6038cc88ed880040146e2fac3 }


condition:
	$a0
}