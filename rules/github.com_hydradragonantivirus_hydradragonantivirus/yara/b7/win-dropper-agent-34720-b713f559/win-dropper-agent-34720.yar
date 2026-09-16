rule Win_Dropper_Agent_34720
{
strings:
	$a0 = { 558bece80000047f6a00ff153c71400033c05dc3cccccccccccccccccccccccccccc558bec64 }


condition:
	$a0
}