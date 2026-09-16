rule Win_Trojan_Lucas_1
{
strings:
	$a0 = { 28aa4615628f45678c95a4d358ec793d65aa46a4d327ec793d65aa46a4d325ec793d6554ae54b5aa }


condition:
	$a0
}