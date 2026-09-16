rule Win_Trojan_QQPass_33
{
strings:
	$a0 = { 68d0070000e80fd2ffff6a006a0068b0754000683c75400068447540006a00e815d4ffff }


condition:
	$a0
}