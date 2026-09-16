rule anti_debug__Exit_the_program_if_its_being_debugged_by_checking_execution_timing__8_byt_19_
{
strings:
	$a0 = { 0f3133c903c80f312bc13dff0f0000eb086a00 }

condition:
	$a0
}