rule Win_Trojan_OneHalf_14
{
strings:
	$a0 = { dd59931734cbe10e0fa2a7caf20c348677440c653a6090ec2570802bb45689cae558eeb8ea38ba2c9f07ee285ea83daa }


condition:
	$a0
}