rule Win_Trojan_VGEN_365
{
strings:
	$a0 = { 03018b0d5133c08ec026803efc04ce7517e856005951b8008050b8260150cb0e1fe85a00590656cb26c606fc04cee8 }


condition:
	$a0
}