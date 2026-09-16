rule Win_Trojan_Agent_35849
{
strings:
	$a0 = { 558becb95b0000006a006a004975f951b87c314000e8feefffff33c055689c46 }

	$a1 = { 6e0069007600650070006500790061 }


condition:
	$a0 and $a1
}