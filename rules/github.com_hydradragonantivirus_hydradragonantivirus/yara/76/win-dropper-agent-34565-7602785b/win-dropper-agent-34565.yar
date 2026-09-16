rule Win_Dropper_Agent_34565
{
strings:
	$a0 = { 558bec83ec548d45e450e8210200008b4de48bd181c22affffff }


condition:
	$a0
}