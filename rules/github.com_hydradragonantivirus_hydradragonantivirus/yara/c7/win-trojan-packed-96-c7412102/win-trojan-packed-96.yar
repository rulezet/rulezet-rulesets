rule Win_Trojan_Packed_96
{
strings:
	$a0 = { 5060e8000000005d81ed0710400068800b00008d851f10400050e8840b0000 }


condition:
	$a0
}