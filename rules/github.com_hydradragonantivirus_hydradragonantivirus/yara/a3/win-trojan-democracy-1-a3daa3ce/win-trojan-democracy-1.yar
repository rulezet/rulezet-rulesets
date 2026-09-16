rule Win_Trojan_Democracy_1
{
strings:
	$a0 = { 52e80000582daa09d1e8d1e8d1e8d1e88cca03c250b8c00950cb5a58e8d4001eb86109e81d00070e1f8c06e709be }


condition:
	$a0
}