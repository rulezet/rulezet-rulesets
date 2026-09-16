rule Win_Trojan_WorkHard_1
{
strings:
	$a0 = { b980060e1f33d2e8fb0072263d80067521b8004233c98bd1e8ea00b440b903000e1fba9905e8 }


condition:
	$a0
}