rule Win_Trojan_Pakes_989
{
strings:
	$a0 = { 686c6c0000686f6e2e64687773686354e8????000083c40c83f8027c0d66b94d5a6633080f84????0000cc11 }


condition:
	$a0
}