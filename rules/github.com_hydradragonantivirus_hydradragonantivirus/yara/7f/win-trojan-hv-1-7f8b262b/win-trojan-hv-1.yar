rule Win_Trojan_HV_1
{
strings:
	$a0 = { be7101bf0b01cd2181fa34127475e830037270b821 }


condition:
	$a0
}