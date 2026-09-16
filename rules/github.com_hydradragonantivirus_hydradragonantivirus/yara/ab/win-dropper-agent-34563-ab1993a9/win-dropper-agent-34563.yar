rule Win_Dropper_Agent_34563
{
strings:
	$a0 = { 558bec83ec548d45e450e8410200008b4de48bd18d0520500a00c1e10e03c125 }


condition:
	$a0
}