rule Win_Trojan_IWorm_1
{
strings:
	$a0 = { e80800fec380fb3f75f1c3fabaf701ec248075fb80ea05b00aeefec2b001eefec288c8eefec288e8 }


condition:
	$a0
}