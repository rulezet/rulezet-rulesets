rule Win_Trojan_Packed_165
{
strings:
	$a0 = { 68646c6c0068696c742e68706e676654e83308000083c40c83f8027c0d66b94d }


condition:
	$a0
}