rule Win_Trojan_V377_1
{
strings:
	$a0 = { 01b600b280b101b500cd138bf381c6be01268a2480fc807503e81000268a641080fc807506 }


condition:
	$a0
}