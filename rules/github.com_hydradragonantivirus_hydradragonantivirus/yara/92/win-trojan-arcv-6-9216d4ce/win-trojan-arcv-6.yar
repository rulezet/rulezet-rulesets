rule Win_Trojan_Arcv_6
{
strings:
	$a0 = { e800005f81ef0701e80200eb128db52301b9b6038cc88ed8 }


condition:
	$a0
}