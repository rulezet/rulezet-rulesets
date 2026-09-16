rule Win_Dropper_Agent_33929
{
strings:
	$a0 = { 0134d06b40af05fdffec7fdfb8c1e5f13f4d7122d538393739310d0a313239302e6578 }


condition:
	$a0
}