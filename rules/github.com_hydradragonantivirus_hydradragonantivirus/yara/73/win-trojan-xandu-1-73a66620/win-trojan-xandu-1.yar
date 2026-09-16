rule Win_Trojan_Xandu_1
{
strings:
	$a0 = { 80026a5fedefed027e1541e67a1dcf53712cf6843b0bc602b0cfa33e817ee7bacc1f3147debbc343 }


condition:
	$a0
}