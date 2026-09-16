rule Win_Spyware_Banker_3313
{
strings:
	$a0 = { 375bc7ed850d066dac90bed3cb67df4ea9e4e4de8503d8199715095a18a169874932bbddf1ceee417fddb7a8fa3221a8f169bb5ed6f02f5ed8b8412b2df658ccf863b59a16db }


condition:
	$a0
}