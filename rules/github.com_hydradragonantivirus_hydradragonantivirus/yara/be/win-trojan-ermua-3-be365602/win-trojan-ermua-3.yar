rule Win_Trojan_Ermua_3
{
strings:
	$a0 = { 5848508f47036bc040500787064e00508f066c7d }


condition:
	$a0
}