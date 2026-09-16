rule Win_Trojan_Transmitter_1
{
strings:
	$a0 = { 51521e069ce80000582d0900ba0000bb1000f7f38ccb03c32d10000e8ed858a3d204b8ffffcd173d00087478b821 }


condition:
	$a0
}