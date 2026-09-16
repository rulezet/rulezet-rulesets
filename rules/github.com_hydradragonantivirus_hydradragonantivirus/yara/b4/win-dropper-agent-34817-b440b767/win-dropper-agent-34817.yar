rule Win_Dropper_Agent_34817
{
strings:
	$a0 = { e8dd010000a3c81b00106a006a00ff3579100010ff35c81b0010e811020000 }


condition:
	$a0
}