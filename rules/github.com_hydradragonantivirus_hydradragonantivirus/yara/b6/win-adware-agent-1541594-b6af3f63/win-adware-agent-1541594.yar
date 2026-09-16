rule Win_Adware_Agent_1541594
{
strings:
	$a0 = { 3c7067387a384839693a5d3b[9]6f3c0c[10]324c34943508da68369636db36[5]2e0a37174f }


condition:
	$a0
}