rule anti_debug__RDTSC_Instruction_Debugger_Latency_Detection__8_byt_15_
{
strings:
	$a0 = { 0f3133c903c80f312bc13dff0f0000 }

condition:
	$a0
}