rule Win_Dropper_Agent_34465
{
strings:
	$a0 = { 558bec8bc083ec1b4c8bdcff15181040008be3ff15001040008945e4053d104000ffe0 }


condition:
	$a0
}