rule Win_Trojan_R_61
{
strings:
	$a0 = { 0201e80000e80d008b360001bcfeff81ee0901eb0f578bfb2bfb8bdf5fb403b005cd16c38bee518bc82bc15980cc66 }


condition:
	$a0
}