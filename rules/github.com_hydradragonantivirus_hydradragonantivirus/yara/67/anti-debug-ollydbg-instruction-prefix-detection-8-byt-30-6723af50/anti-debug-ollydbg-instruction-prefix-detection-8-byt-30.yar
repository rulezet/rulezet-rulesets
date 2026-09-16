rule anti_debug__OllyDbg_Instruction_Prefix_Detection__8_byt_30_
{
strings:
	$a0 = { 64ff350000000064892500000000f364f1648f050000000083c404616a30 }

condition:
	$a0
}