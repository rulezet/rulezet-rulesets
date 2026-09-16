rule Win_Trojan_V_29
{
strings:
	$a0 = { 03562d751726813ecc03314c750e36c7068001000036 }


condition:
	$a0
}