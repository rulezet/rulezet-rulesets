rule Win_Trojan_Rusty_1
{
strings:
	$a0 = { 06008bec9c8076ff018bfe81c747009d2e8a2429ee0321d61346052bc6490056843024ec48fa }


condition:
	$a0
}