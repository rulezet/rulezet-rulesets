rule Win_Dropper_Agent_34703
{
strings:
	$a0 = { 558bec83c4f053b8e8cd4800e814004ff88b1dd80549008b03e814056cf8[0-90]43616978612045636f6e }


condition:
	$a0
}