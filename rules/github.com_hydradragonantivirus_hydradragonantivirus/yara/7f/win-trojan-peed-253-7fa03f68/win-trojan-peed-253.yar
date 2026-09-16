rule Win_Trojan_Peed_253
{
strings:
	$a0 = { 3ad8bd2d5c1100f7df3bcfc1dfca8d1d }


condition:
	$a0
}