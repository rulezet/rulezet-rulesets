rule Win_Trojan_W_378
{
strings:
	$a0 = { 609cfce8000000005d83ed08b0??b91d0600008d751b300646e2fb }


condition:
	$a0
}