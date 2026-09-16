rule Win_Trojan_Zombie_8
{
strings:
	$a0 = { 03dbdb785cc8c3e38b5b015bff5b0f5ba8919ce3940cdd0bdf21fdd6033bdb0325da0364daa891d4259adb }


condition:
	$a0
}