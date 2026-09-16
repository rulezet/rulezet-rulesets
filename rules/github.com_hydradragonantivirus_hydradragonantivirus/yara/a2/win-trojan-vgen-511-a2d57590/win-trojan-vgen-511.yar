rule Win_Trojan_VGEN_511
{
strings:
	$a0 = { cd218ec3263b1e160075358bda8a0750b42fcd2158fec0750383c307268a4717241f341d751a }


condition:
	$a0
}