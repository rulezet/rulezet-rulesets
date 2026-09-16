rule Win_Trojan_DKiller_3
{
strings:
	$a0 = { 04008d96ec02cd213e81beec02cce975068d86aa01 }


condition:
	$a0
}