rule Win_Dropper_Agent_34136
{
strings:
	$a0 = { 6a00a1ac784000e8dfeaffff8bd8538d55b433c0e812deffff8b45b4e8caeaffff50e884f0ffff6a006a008d55b033c0e8f6ddffff8b45b0e8aeeaffff505368a04f40006a00e890faffff }


condition:
	$a0
}