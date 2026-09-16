rule Win_Trojan_Kusumah_1
{
strings:
	$a0 = { b80102cd13720c51e80900597205b80103cd13c3b91000f6450b087511803de5740cf605ff }


condition:
	$a0
}