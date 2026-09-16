rule Win_Trojan_IRC_Script_54
{
strings:
	$a0 = { 5b69676e6f72655d0d0a6e303d2a212a402a2c6463630d0a0d0a5b6f705d0d0a0d0a5b766f6963655d0d0a0d0a5b70726f746563745d0d0a }


condition:
	$a0
}