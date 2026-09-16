rule Win_Trojan_Virut_208
{
strings:
	$a0 = { 90e81c00000053b9980c00008bda6631108d14138d4002e2f55bc35dc3 }


condition:
	$a0
}