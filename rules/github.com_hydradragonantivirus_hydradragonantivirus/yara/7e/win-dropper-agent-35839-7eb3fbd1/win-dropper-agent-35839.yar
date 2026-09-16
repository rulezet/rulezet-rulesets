rule Win_Dropper_Agent_35839
{
strings:
	$a0 = { 807c2408010f85e70b000060be00d005118dbe0040faff5789e58d9c2480c1ff }

	$a1 = { 48e5666c617368637078 }


condition:
	$a0 and $a1
}